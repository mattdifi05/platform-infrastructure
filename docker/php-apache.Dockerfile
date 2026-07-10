# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG PHP_IMAGE=php:8.5-apache@sha256:c6e17deefe4b7f79fd6a826a3d5f61f28035c3a7c12a1b446bf45f0e07bee9b2
ARG COMPOSER_IMAGE=composer:2.10.1@sha256:7725eb4545c438629ae8bde3ef0bb9a5038ef566126ad878442a69007242d267
ARG PHP_EXTENSION_INSTALLER_IMAGE=mlocati/php-extension-installer:2.11.12@sha256:b6d3fa381b9ba5cf051117c1c601d6a523b590e534bf3d56eb4fbe352949c138

FROM ${COMPOSER_IMAGE} AS composer
FROM ${PHP_EXTENSION_INSTALLER_IMAGE} AS php-extension-installer
FROM ${PHP_IMAGE}

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

# Apache modules (SSL + reverse proxy + dynamic project vhosts)
RUN a2enmod rewrite ssl headers proxy proxy_http vhost_alias

# OS deps (ImageMagick CLI + dev libs for imagick, + tools)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip zip \
    imagemagick libmagickwand-dev libmagickcore-dev \
 && rm -rf /var/lib/apt/lists/*

# Install "install-php-extensions" from a digest-pinned helper image.
COPY --from=php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/install-php-extensions

# Sanity check: script must be executable and callable
RUN command -v install-php-extensions \
 && install-php-extensions --version || true

# Install bundled/common extensions + MySQL + others
# (If any extension fails, build FAILS and you see the exact reason)
RUN install-php-extensions \
  bcmath \
  bz2 \
  calendar \
  dba \
  enchant \
  exif \
  ffi \
  ftp \
  gd \
  gettext \
  gmp \
  intl \
  ldap \
  mysqli \
  opcache \
  pcntl \
  pdo_mysql \
  shmop \
  snmp \
  soap \
  sockets \
  sodium \
  sysvmsg \
  sysvsem \
  sysvshm \
  tidy \
  xsl \
  zip

# imagick (PHP extension) - requires ImageMagick headers (already installed above)
ARG IMAGICK_VERSION=3.8.1
ARG IMAGICK_SHA256=3a3587c0a524c17d0dad9673a160b90cd776e836838474e173b549ed864352ee
RUN apt-get update \
 && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
 && mkdir -p /usr/src/php/ext/imagick \
 && curl -fsSL -o /tmp/imagick.tgz "https://pecl.php.net/get/imagick-${IMAGICK_VERSION}.tgz" \
 && printf '%s  %s\n' "$IMAGICK_SHA256" /tmp/imagick.tgz | sha256sum -c - \
 && tar -xzf /tmp/imagick.tgz -C /usr/src/php/ext/imagick --strip-components=1 \
 && cd /usr/src/php/ext/imagick \
 && phpize \
 && ./configure --with-php-config=/usr/local/bin/php-config --with-imagick \
 && find . -maxdepth 1 -name "*_arginfo.h" -exec touch {} + \
 && make -j"$(nproc)" \
 && find . -maxdepth 1 -name "*_arginfo.h" -exec touch {} + \
 && make install \
 && docker-php-ext-enable imagick \
 && cd / \
 && rm -rf /usr/src/php/ext/imagick /tmp/imagick.tgz \
 && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $PHPIZE_DEPS \
 && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
RUN composer --version

# Enable HTTPS site and plain HTTP redirect site
RUN a2ensite 000-default default-ssl

COPY php-apache/apache/zz-server-hardening.conf /etc/apache2/conf-available/zz-server-hardening.conf
COPY php-apache/php/conf.d/zz-production.ini /usr/local/etc/php/conf.d/zz-production.ini
RUN a2enconf zz-server-hardening

WORKDIR /var/www/html
