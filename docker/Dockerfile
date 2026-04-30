# ---- Composer stage: install prod dependencies ----
FROM composer:2 AS vendor

WORKDIR /var/www/html
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

# ---- Composer stage: install all dependencies (including dev) ----
FROM composer:2 AS vendor-dev

WORKDIR /var/www/html
COPY composer.json composer.lock ./
RUN composer install --no-scripts --no-autoloader --prefer-dist

# ---- Production stage ----
FROM ghcr.io/openconext/openconext-basecontainers/php85-apache2:latest AS prod

RUN pecl install apcu \
    && docker-php-ext-enable apcu \
    && rm -rf /tmp/pear

WORKDIR /var/www/html

ENV COMPOSER_HOME=/tmp/composer \
    APP_ENV=prod \
    DEFAULT_URI=http://localhost

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY --from=vendor /var/www/html/vendor ./vendor
COPY .env composer.json composer.lock symfony.lock ./
COPY bin/ ./bin/
COPY config/ ./config/
COPY public/ ./public/
COPY src/ ./src/
COPY templates/ ./templates/
RUN composer dump-autoload --optimize --classmap-authoritative

COPY docker/app.ini /usr/local/etc/php/conf.d/app.ini
COPY docker/apache-app.conf /etc/apache2/sites-enabled/000-default.conf

COPY docker/entrypoint-app.sh /entrypoint-app.sh
RUN chmod +x /entrypoint-app.sh
ENTRYPOINT ["/entrypoint-app.sh"]

# ---- Development stage (extends prod with all dev tooling) ----
FROM prod AS dev

COPY --from=vendor-dev /var/www/html/vendor ./vendor
COPY tests/ ./tests/
COPY phpcs.xml phpunit.xml.dist phpstan.neon phpstan-baseline.neon .phplint.yml ./
RUN composer dump-autoload \
    && chown -R www-data:www-data /var/www/html
