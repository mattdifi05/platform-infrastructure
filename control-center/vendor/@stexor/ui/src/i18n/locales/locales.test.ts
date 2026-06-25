import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { deDE } from "./de-DE";
import { enUS } from "./en-US";
import { esES } from "./es-ES";
import { frFR } from "./fr-FR";
import { itIT } from "./it-IT";

const localeDir = path.dirname(fileURLToPath(import.meta.url));
type LocaleKey = keyof typeof itIT;
type LocaleDictionary = Record<LocaleKey, string>;
const expectedKeys = (Object.keys(itIT) as LocaleKey[]).sort();

const dictionaries: ReadonlyArray<readonly [string, LocaleDictionary]> = [
  ["it-IT", itIT],
  ["en-US", enUS],
  ["de-DE", deDE],
  ["fr-FR", frFR],
  ["es-ES", esES],
];

const sourceFiles = [
  ["it-IT", "it-IT.ts"],
  ["en-US", "en-US.ts"],
  ["de-DE", "de-DE.ts"],
  ["fr-FR", "fr-FR.ts"],
  ["es-ES", "es-ES.ts"],
] as const;

function explicitKeys(fileName: string) {
  const source = fs.readFileSync(path.join(localeDir, fileName), "utf8");
  return [...source.matchAll(/^\s*"([^"]+)":\s*"/gm)].map((match) => match[1]).sort();
}

function placeholders(value: string) {
  return [...value.matchAll(/\{[a-zA-Z0-9_]+\}/g)].map((match) => match[0]).sort();
}

test("locale dictionaries expose exactly the Italian reference keys", () => {
  for (const [locale, dictionary] of dictionaries) {
    assert.deepEqual(Object.keys(dictionary).sort(), expectedKeys, locale);
  }
});

test("locale source files explicitly translate every Italian reference key", () => {
  for (const [locale, fileName] of sourceFiles) {
    const keys = explicitKeys(fileName);
    assert.equal(new Set(keys).size, keys.length, `${locale} has duplicate translation keys`);
    assert.deepEqual(keys, expectedKeys, locale);
  }
});

test("locale placeholders stay aligned with the Italian reference", () => {
  for (const [locale, dictionary] of dictionaries) {
    for (const key of expectedKeys) {
      assert.deepEqual(placeholders(dictionary[key]), placeholders(itIT[key]), `${locale}:${key}`);
    }
  }
});

test("locale source files do not contain mojibake markers", () => {
  for (const [locale, fileName] of sourceFiles) {
    const source = fs.readFileSync(path.join(localeDir, fileName), "utf8");
    assert.equal(/Ãƒ|ï¿½/.test(source), false, locale);
  }
});

