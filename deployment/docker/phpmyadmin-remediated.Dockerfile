FROM phpmyadmin:5.2.3@sha256:0b38dba8580a95729813799e36623042ac5e23af19d8c50f8003b19f4b980726 AS runtime
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
FROM runtime AS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git unzip && rm -rf /var/lib/apt/lists/*
COPY --from=platform/php-apache:remediation-php8511 /usr/local/bin/composer /tmp/composer
WORKDIR /var/www/html
COPY deployment/phpmyadmin/composer.json deployment/phpmyadmin/composer.lock ./
RUN COMPOSER_ALLOW_SUPERUSER=1 php /tmp/composer install --no-dev --no-interaction --no-plugins --no-scripts --prefer-dist --no-progress \
 && php /tmp/composer check-platform-reqs --no-dev \
 && php /tmp/composer audit --no-dev --format=json \
 && rm /tmp/composer
FROM runtime
RUN rm -rf /var/www/html/vendor
COPY --from=dependencies /var/www/html/vendor /var/www/html/vendor
COPY --from=dependencies /var/www/html/composer.json /var/www/html/composer.lock /var/www/html/
