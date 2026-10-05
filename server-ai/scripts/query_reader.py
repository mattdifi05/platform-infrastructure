#!/usr/bin/env python3
"""Private SQL AST gate and read-only executor for registered project databases."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import ssl
import threading
from typing import Any

try:
    from server_ai_reader_common import ReaderError, exact_object, load_token, serve
except ImportError:  # local tests
    from common import ReaderError, exact_object, load_token, serve

try:
    import pymysql
    import pg8000.dbapi as pg8000
    from sqlglot import exp, parse
except ImportError:  # Unit tests can import pure validation with dependencies installed separately.
    pymysql = None
    pg8000 = None
    exp = None
    parse = None


DATABASES = {
    "fiplatform-mariadb-fiplatform": {
        "projectId": "fiplatform", "dialect": "mariadb", "driver": "mariadb",
        "host": "mariadb", "port": 3306, "database": "fiplatform",
        "secret": Path("/run/secrets/server_ai_fiplatform_mariadb_fiplatform_ro"),
    },
    "fiplatform-mariadb-u778675014-fip": {
        "projectId": "fiplatform", "dialect": "mariadb", "driver": "mariadb",
        "host": "mariadb", "port": 3306, "database": "u778675014_fip",
        "secret": Path("/run/secrets/server_ai_fiplatform_mariadb_u778675014_fip_ro"),
    },
    "workcalendar-mariadb-workcalendar": {
        "projectId": "workcalendar", "dialect": "mariadb", "driver": "mariadb",
        "host": "mariadb", "port": 3306, "database": "workcalendar",
        "secret": Path("/run/secrets/server_ai_workcalendar_mariadb_workcalendar_ro"),
    },
    "anniversary-mariadb-anniversary": {
        "projectId": "anniversary", "dialect": "mariadb", "driver": "mariadb",
        "host": "mariadb", "port": 3306, "database": "anniversary",
        "secret": Path("/run/secrets/server_ai_anniversary_mariadb_anniversary_ro"),
    },
    "stream-mariadb-stream": {
        "projectId": "stream", "dialect": "mariadb", "driver": "mariadb",
        "host": "mariadb", "port": 3306, "database": "stream",
        "secret": Path("/run/secrets/server_ai_stream_mariadb_stream_ro"),
    },
    # account-postgres-stexor is intentionally exposed through the canonical
    # managed source root, not through its container or application aliases.
    "account-postgres-stexor": {
        "projectId": "stexor", "dialect": "postgresql", "driver": "postgresql",
        "host": "postgres", "port": 5432, "database": "stexor",
        "schemas": ("stexor_account", "stexor_platform"),
        "secret": Path("/run/secrets/server_ai_account_postgres_stexor_ro"),
    },
}
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,63}$")
PLACEHOLDER = re.compile(r"^p([1-9]|[12][0-9]|3[0-2])$")
PARAM_SENTINEL = re.compile(r"__SERVER_AI_PARAM_([1-9]|[12][0-9]|3[0-2])__")
COMMENT = re.compile(r"(?:--|#|/\*|\*/)")
SENSITIVE = re.compile(r"(?i)(?:passw|passwd|secret|token|credential|session|auth|private.?key|api.?key|salt|hash|remember.?token|oauth|config|setting)")
SENSITIVE_VALUE = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://[^\s:@]+:[^\s@]+@|authorization\s*[:=]|bearer\s+[A-Za-z0-9._~-]{8,}|(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]{4,})")
SAFE_FUNCTIONS = frozenset({
    "abs", "avg", "ceil", "ceiling", "coalesce", "concat", "concat_ws", "count", "date",
    "date_format", "date_trunc", "day", "floor", "greatest", "least", "length", "lower",
    "ltrim", "max", "min", "month", "nullif", "replace", "round", "rtrim", "substring",
    "sum", "trim", "upper", "year",
})
MAX_ROWS = 200
MAX_RESULT_BYTES = 128 * 1024
MAX_SCHEMA_CONTENT_BYTES = 30 * 1024
MAX_SQL_BYTES = 4000
MAX_PARAM_BYTES = 16 * 1024
QUERY_TIMEOUT_SECONDS = 3


def _credential(path: Path) -> tuple[str, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(raw) > 4096:
        raise RuntimeError("database credential is invalid")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("database credential is invalid") from None
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise RuntimeError("database credential is invalid")
    username, password = value["username"], value["password"]
    if not isinstance(username, str) or not IDENTIFIER.fullmatch(username) or not isinstance(password, str) or not 16 <= len(password) <= 512 or "\x00" in password:
        raise RuntimeError("database credential is invalid")
    return username, password


def _database_tls_ca_file() -> str:
    ca_file = Path(os.environ.get("SERVER_AI_DB_TLS_CA_FILE", "/run/platform-db-tls/ca.crt"))
    try:
        if not ca_file.is_file():
            raise RuntimeError("database TLS CA is unavailable")
        with ca_file.open("rb") as handle:
            handle.read(1)
    except OSError as error:
        raise RuntimeError("database TLS CA is unavailable") from error
    return str(ca_file)


def _safe_param(value: Any) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, str) and len(value) <= 2048 and "\x00" not in value:
        return value
    raise ReaderError("INPUT_LIMIT")


def _sensitive_name(value: str) -> bool:
    return bool(SENSITIVE.search(value.replace("`", "").replace('"', "")))


def validate_sql(sql: Any, dialect: Any, params: Any, allowed_schemas: tuple[str, ...] = ()) -> tuple[str, list[Any]]:
    if parse is None or exp is None:
        raise RuntimeError("SQL parser is unavailable")
    if dialect not in {"mariadb", "postgresql"} or not isinstance(sql, str) or not sql.strip() or len(sql.encode("utf-8")) > MAX_SQL_BYTES or "\x00" in sql or COMMENT.search(sql) or "__SERVER_AI_PARAM_" in sql.upper():
        raise ReaderError("QUERY_REJECTED")
    if not isinstance(params, list) or len(params) > 32:
        raise ReaderError("INPUT_LIMIT")
    values = [_safe_param(value) for value in params]
    if len(json.dumps(values, ensure_ascii=False).encode("utf-8")) > MAX_PARAM_BYTES:
        raise ReaderError("INPUT_LIMIT")
    try:
        statements = parse(sql, read="mysql" if dialect == "mariadb" else "postgres")
    except Exception:
        raise ReaderError("QUERY_REJECTED") from None
    if len(statements) != 1 or not isinstance(statements[0], exp.Query):
        raise ReaderError("QUERY_REJECTED")
    statement = statements[0]
    denied_types = tuple(
        cls for name in (
            "Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter", "Command", "Copy",
            "Into", "Lock", "Transaction", "Commit", "Rollback", "Grant", "Revoke", "Use", "Execute",
            "LoadData", "Pragma", "Set", "Show", "Describe", "TruncateTable",
        ) if (cls := getattr(exp, name, None)) is not None
    )
    placeholders: list[int] = []
    for node in statement.walk():
        if denied_types and isinstance(node, denied_types):
            raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Table):
            if (node.catalog or not IDENTIFIER.fullmatch(node.name or "") or _sensitive_name(node.name)
                    or (node.db and (dialect != "postgresql" or node.db not in allowed_schemas))):
                raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Column):
            if node.is_star:
                parent = node.parent
                if not isinstance(parent, exp.Count):
                    raise ReaderError("QUERY_REJECTED")
            elif not IDENTIFIER.fullmatch(node.name or "") or _sensitive_name(node.name):
                raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Star):
            parent = node.parent
            if not isinstance(parent, exp.Count):
                raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Alias) and _sensitive_name(node.alias or ""):
            raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Func):
            name = node.sql_name().casefold()
            if name not in SAFE_FUNCTIONS:
                raise ReaderError("QUERY_REJECTED")
        if isinstance(node, exp.Placeholder):
            match = PLACEHOLDER.fullmatch(str(node.this or ""))
            if not match:
                raise ReaderError("QUERY_REJECTED")
            placeholders.append(int(match.group(1)))
    if sorted(set(placeholders)) != list(range(1, len(values) + 1)) or len(placeholders) != len(values):
        raise ReaderError("QUERY_REJECTED")
    # Placeholders are rewritten by AST, never by string interpolation.
    def rewrite(node):
        if isinstance(node, exp.Placeholder):
            return exp.Var(this=f"__SERVER_AI_PARAM_{int(PLACEHOLDER.fullmatch(str(node.this)).group(1))}__")
        return node
    rendered = statement.transform(rewrite, copy=True).sql(dialect="mysql" if dialect == "mariadb" else "postgres", pretty=False)
    rendered_order = [int(match.group(1)) for match in PARAM_SENTINEL.finditer(rendered)]
    rendered = PARAM_SENTINEL.sub("%s", rendered)
    if len(rendered.encode("utf-8")) > MAX_SQL_BYTES or ";" in rendered or sorted(rendered_order) != list(range(1, len(values) + 1)):
        raise ReaderError("QUERY_REJECTED")
    ordered = [values[index - 1] for index in rendered_order]
    return rendered, ordered


def _safe_value(value: Any) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).hex()
    elif not isinstance(value, str):
        value = str(value)
    value = value[:4096]
    return "[REDACTED]" if SENSITIVE_VALUE.search(value) else value


class QueryReader:
    def __init__(self, databases: dict[str, dict[str, Any]] = DATABASES, token: bytes | None = None,
                 connectors: dict[str, Any] | None = None):
        if not databases or set(databases) - set(DATABASES):
            raise RuntimeError("query reader databases are invalid")
        self.databases = databases
        self.token = token if token is not None else load_token()
        self.connectors = connectors or {"mariadb": self._connect_mariadb, "postgresql": self._connect_postgresql}
        self.lock = threading.BoundedSemaphore(2)

    @staticmethod
    def _connect_mariadb(config: dict[str, Any], username: str, password: str):
        if pymysql is None:
            raise RuntimeError("MariaDB driver is unavailable")
        ca_file = _database_tls_ca_file()
        return pymysql.connect(host=config["host"], port=config["port"], user=username, password=password,
                               database=config["database"], connect_timeout=3, read_timeout=5, write_timeout=5,
                               charset="utf8mb4", autocommit=False, cursorclass=pymysql.cursors.SSCursor,
                               ssl_ca=ca_file, ssl_verify_cert=True, ssl_verify_identity=True)

    @staticmethod
    def _connect_postgresql(config: dict[str, Any], username: str, password: str):
        if pg8000 is None:
            raise RuntimeError("PostgreSQL driver is unavailable")
        ca_file = _database_tls_ca_file()
        tls_context = ssl.create_default_context(cafile=ca_file)
        tls_context.check_hostname = True
        tls_context.verify_mode = ssl.CERT_REQUIRED
        return pg8000.connect(host=config["host"], port=config["port"], user=username, password=password,
                              database=config["database"], timeout=3, ssl_context=tls_context)

    def _connection(self, config: dict[str, Any]):
        username, password = _credential(config["secret"])
        return self.connectors[config["driver"]](config, username, password)

    @staticmethod
    def _begin_read_only(connection, driver: str, schemas: tuple[str, ...] = ()):
        cursor = connection.cursor()
        if driver == "mariadb":
            cursor.execute("SET SESSION TRANSACTION READ ONLY")
            cursor.execute(f"SET SESSION max_statement_time={QUERY_TIMEOUT_SECONDS}")
            cursor.execute("START TRANSACTION READ ONLY")
        else:
            cursor.execute("BEGIN READ ONLY")
            cursor.execute(f"SET LOCAL statement_timeout = {QUERY_TIMEOUT_SECONDS * 1000}")
            cursor.execute("SET LOCAL lock_timeout = 1000")
            if schemas:
                cursor.execute("SET LOCAL search_path TO " + ", ".join(schemas))
        return cursor

    @staticmethod
    def _fetch(cursor, limit: int = MAX_ROWS) -> tuple[list[str], list[list[Any]]]:
        if cursor.description is None:
            raise ReaderError("QUERY_REJECTED")
        raw_columns = [str(item[0]) for item in cursor.description]
        if len(raw_columns) > 64 or any(_sensitive_name(column) for column in raw_columns):
            raise ReaderError("QUERY_REJECTED")
        columns = [column if IDENTIFIER.fullmatch(column) else f"value_{index + 1}" for index, column in enumerate(raw_columns)]
        if len(set(columns)) != len(columns):
            columns = [f"value_{index + 1}" for index in range(len(columns))]
        fetched = cursor.fetchmany(limit + 1)
        if len(fetched) > limit:
            raise ReaderError("RESULT_LIMIT", 413)
        rows = []
        for row in fetched:
            values = list(row.values()) if isinstance(row, dict) else list(row)
            rows.append([_safe_value(value) for value in values])
        return columns, rows

    @staticmethod
    def _filter_schema(columns: list[str], rows: list[list[Any]]) -> list[list[Any]]:
        checked = [index for index, name in enumerate(columns) if name in {"table_name", "column_name", "index_name", "referenced_table_name", "referenced_column_name"}]
        return [row for row in rows if all(row[index] is None or not _sensitive_name(str(row[index])) for index in checked)]

    @staticmethod
    def _objects(columns: list[str], rows: list[list[Any]]) -> list[dict[str, Any]]:
        if any(len(row) != len(columns) for row in rows):
            raise ReaderError("DB_UNAVAILABLE", 503)
        return [dict(zip(columns, row)) for row in rows]

    def _execute(self, config: dict[str, Any], sql: str, params: list[Any], *, limit: int = MAX_ROWS) -> tuple[list[str], list[list[Any]]]:
        connection = self._connection(config)
        try:
            cursor = self._begin_read_only(connection, config["driver"], tuple(config.get("schemas", ())))
            cursor.execute(sql, params)
            return self._fetch(cursor, limit)
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def _database(self, body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        database_id = body["databaseId"]
        config = self.databases.get(database_id) if isinstance(database_id, str) else None
        if config is None or body["projectId"] != config["projectId"] or body["dialect"] != config["dialect"]:
            raise ReaderError("DB_UNAVAILABLE", 404)
        return database_id, config

    def _item(self, project_id: str, database_id: str, kind: str, value: Any) -> dict[str, Any]:
        normalized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(normalized.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ReaderError("RESULT_LIMIT", 413)
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        source_id = hmac.digest(self.token, f"database\0{project_id}\0{database_id}\0{kind}\0{digest}".encode(), "sha256").hex()
        return {"sourceId": source_id, "kind": "database", "title": f"{database_id}: {kind}", "path": "", "sha256": digest, "content": normalized}

    def _guard(self):
        if not self.lock.acquire(timeout=0.05):
            raise ReaderError("DB_UNAVAILABLE", 429)

    def query(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "databaseId", "dialect", "sql", "params"}, {"projectId", "databaseId", "dialect", "sql", "params"})
        database_id, config = self._database(body)
        sql, params = validate_sql(body["sql"], body["dialect"], body["params"], tuple(config.get("schemas", ())))
        sql = f"SELECT * FROM ({sql}) AS server_ai_bounded LIMIT {MAX_ROWS + 1}"
        self._guard()
        try:
            columns, rows = self._execute(config, sql, params)
        except ReaderError:
            raise
        except Exception:
            raise ReaderError("DB_UNAVAILABLE", 503) from None
        finally:
            self.lock.release()
        item = self._item(body["projectId"], database_id, "query", {"databaseId": database_id, "columns": columns, "rows": rows})
        return {"available": True, "projectId": body["projectId"], "items": [item]}

    def explain(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "databaseId", "dialect", "sql", "params"}, {"projectId", "databaseId", "dialect", "sql", "params"})
        database_id, config = self._database(body)
        sql, params = validate_sql(body["sql"], body["dialect"], body["params"], tuple(config.get("schemas", ())))
        sql = f"SELECT * FROM ({sql}) AS server_ai_bounded LIMIT {MAX_ROWS + 1}"
        self._guard()
        try:
            columns, rows = self._execute(config, f"EXPLAIN {sql}", params, limit=100)
        except ReaderError:
            raise
        except Exception:
            raise ReaderError("DB_UNAVAILABLE", 503) from None
        finally:
            self.lock.release()
        item = self._item(body["projectId"], database_id, "explain", {"databaseId": database_id, "columns": columns, "rows": rows})
        return {"available": True, "projectId": body["projectId"], "items": [item]}

    def schema(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "databaseId", "dialect"}, {"projectId", "databaseId", "dialect"})
        database_id, config = self._database(body)
        if config["driver"] == "mariadb":
            statements = {
                "tables": ("SELECT table_name, table_rows, data_length, index_length FROM information_schema.tables WHERE table_schema=%s AND table_type='BASE TABLE' ORDER BY table_name LIMIT 256", 256),
                "columns": ("SELECT table_name, column_name, data_type, is_nullable, column_key FROM information_schema.columns WHERE table_schema=%s ORDER BY table_name, ordinal_position LIMIT 2048", 2048),
                "indexes": ("SELECT table_name, index_name, non_unique, seq_in_index, column_name FROM information_schema.statistics WHERE table_schema=%s ORDER BY table_name, index_name, seq_in_index LIMIT 4096", 4096),
                "relationships": ("SELECT table_name, column_name, referenced_table_name, referenced_column_name FROM information_schema.key_column_usage WHERE table_schema=%s AND referenced_table_name IS NOT NULL ORDER BY table_name, column_name LIMIT 1024", 1024),
            }
        else:
            schemas = tuple(config.get("schemas", ()))
            if schemas != ("stexor_account", "stexor_platform"):
                raise ReaderError("DB_UNAVAILABLE", 404)
            schema_list = "'stexor_account','stexor_platform'"
            statements = {
                "tables": (f"SELECT n.nspname AS table_schema, c.relname AS table_name, c.reltuples::bigint AS table_rows, pg_total_relation_size(c.oid) AS data_length, pg_indexes_size(c.oid) AS index_length FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ({schema_list}) AND c.relkind='r' ORDER BY n.nspname, c.relname LIMIT 256", 256),
                "columns": (f"SELECT table_schema, table_name, column_name, data_type, is_nullable, '' AS column_key FROM information_schema.columns WHERE table_schema IN ({schema_list}) ORDER BY table_schema, table_name, ordinal_position LIMIT 2048", 2048),
                "indexes": (f"SELECT n.nspname AS table_schema, t.relname AS table_name, i.relname AS index_name, NOT x.indisunique AS non_unique, key_columns.ordinality AS seq_in_index, a.attname AS column_name FROM pg_index x JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_class i ON i.oid=x.indexrelid JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS key_columns(attnum, ordinality) ON TRUE JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key_columns.attnum WHERE n.nspname IN ({schema_list}) ORDER BY n.nspname, t.relname, i.relname, key_columns.ordinality LIMIT 4096", 4096),
                "relationships": (f"SELECT source_schema.nspname AS table_schema, source_table.relname AS table_name, source_column.attname AS column_name, target_schema.nspname AS referenced_table_schema, target_table.relname AS referenced_table_name, target_column.attname AS referenced_column_name FROM pg_constraint fk JOIN pg_class source_table ON source_table.oid=fk.conrelid JOIN pg_namespace source_schema ON source_schema.oid=source_table.relnamespace JOIN pg_class target_table ON target_table.oid=fk.confrelid JOIN pg_namespace target_schema ON target_schema.oid=target_table.relnamespace JOIN LATERAL unnest(fk.conkey) WITH ORDINALITY AS source_keys(attnum, ordinality) ON TRUE JOIN LATERAL unnest(fk.confkey) WITH ORDINALITY AS target_keys(attnum, ordinality) ON target_keys.ordinality=source_keys.ordinality JOIN pg_attribute source_column ON source_column.attrelid=source_table.oid AND source_column.attnum=source_keys.attnum JOIN pg_attribute target_column ON target_column.attrelid=target_table.oid AND target_column.attnum=target_keys.attnum WHERE fk.contype='f' AND source_schema.nspname IN ({schema_list}) AND target_schema.nspname IN ({schema_list}) ORDER BY source_schema.nspname, source_table.relname, fk.conname, source_keys.ordinality LIMIT 1024", 1024),
            }
        self._guard()
        connection = None
        try:
            connection = self._connection(config)
            cursor = self._begin_read_only(connection, config["driver"], tuple(config.get("schemas", ())))
            raw: dict[str, list[dict[str, Any]]] = {}
            for key, (sql, limit) in statements.items():
                params = [config["database"]] if "%s" in sql and config["driver"] == "mariadb" else []
                cursor.execute(sql, params)
                columns, rows = self._fetch(cursor, limit)
                raw[key] = self._objects(columns, self._filter_schema(columns, rows))
        except ReaderError:
            raise
        except Exception:
            raise ReaderError("DB_UNAVAILABLE", 503) from None
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()
            self.lock.release()
        result = {
            "schemaVersion": 1, "databaseId": database_id, "dialect": config["dialect"],
            "tables": [{"name": (str(row.get("table_schema")) + "." if row.get("table_schema") else "") + row["table_name"]} for row in raw["tables"]],
            "columns": [{"table": (str(row.get("table_schema")) + "." if row.get("table_schema") else "") + row["table_name"], "name": row["column_name"], "type": row["data_type"], "nullable": row["is_nullable"] == "YES", "key": row.get("column_key", "")} for row in raw["columns"]],
            "indexes": [{"table": (str(row.get("table_schema")) + "." if row.get("table_schema") else "") + row["table_name"], "name": row["index_name"], "unique": row.get("non_unique") in {0, False}, "position": row.get("seq_in_index"), "column": row.get("column_name"), "definition": row.get("indexdef")} for row in raw["indexes"]],
            "relationships": [{"table": (str(row.get("table_schema")) + "." if row.get("table_schema") else "") + row["table_name"], "column": row["column_name"], "referencedTable": (str(row.get("referenced_table_schema")) + "." if row.get("referenced_table_schema") else "") + row["referenced_table_name"], "referencedColumn": row["referenced_column_name"]} for row in raw["relationships"]],
            "stats": [{"table": (str(row.get("table_schema")) + "." if row.get("table_schema") else "") + row["table_name"], "estimatedRows": row.get("table_rows"), "dataBytes": row.get("data_length"), "indexBytes": row.get("index_length")} for row in raw["tables"]],
        }
        result["truncated"] = False
        while len(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")) > MAX_SCHEMA_CONTENT_BYTES:
            largest = max((key for key in ("columns", "indexes", "relationships", "stats", "tables") if result[key]), key=lambda key: len(result[key]), default=None)
            if largest is None:
                raise ReaderError("RESULT_LIMIT", 413)
            result[largest].pop()
            result["truncated"] = True
        item = self._item(body["projectId"], database_id, "schema", result)
        return {"available": True, "projectId": body["projectId"], "items": [item]}

    def routes(self):
        return {"/v1/db/query": self.query, "/v1/db/explain": self.explain, "/v1/db/schema": self.schema}


def main() -> None:
    reader = QueryReader()
    serve(8111, reader.token, reader.routes())


if __name__ == "__main__":
    main()
