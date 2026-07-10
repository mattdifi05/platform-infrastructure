#!/usr/bin/env sh
set -eu

slug=${PHP_PROJECT_RUNTIME_SLUG:?Set PHP_PROJECT_RUNTIME_SLUG}
source_dir=${PHP_PROJECT_SOURCE_DIR:-/opt/platform-source/$slug}
runtime_root=${PHP_PROJECT_RUNTIME_ROOT:-/var/www/projects}
runtime_dir=$runtime_root/$slug
aliases=${PHP_PROJECT_RUNTIME_ALIASES:-}

case "$slug" in
  *[!a-z0-9-]*|'')
    echo "Invalid PHP project runtime slug." >&2
    exit 64
    ;;
esac
case "$source_dir" in
  /opt/platform-source/*) ;;
  *)
    echo "PHP project source must stay below /opt/platform-source." >&2
    exit 64
    ;;
esac
case "$runtime_root" in
  /var/www/projects) ;;
  *)
    echo "PHP project runtime root must be /var/www/projects." >&2
    exit 64
    ;;
esac

if [ ! -d "$source_dir" ]; then
  echo "PHP project source is missing: $source_dir" >&2
  exit 66
fi

umask 0027
mkdir -p "$runtime_dir"
find "$runtime_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
cp -a "$source_dir/." "$runtime_dir/"
chown -R www-data:www-data "$runtime_dir"
chmod -R u=rwX,go=rX "$runtime_dir"

for alias in $(printf '%s' "$aliases" | tr ',' ' '); do
  case "$alias" in
    *[!a-z0-9-]*|'')
      echo "Invalid PHP project runtime alias." >&2
      exit 64
      ;;
  esac
  ln -s "$slug" "$runtime_root/$alias"
done

exec docker-php-entrypoint "$@"

