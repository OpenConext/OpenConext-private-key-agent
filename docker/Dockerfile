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

ENV COMPOSER_HOME=/tmp/composer

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY --from=vendor /var/www/html/vendor ./vendor
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

COPY docker/app.ini /usr/local/etc/php/conf.d/app.ini
COPY docker/apache-app.conf /etc/apache2/sites-enabled/000-default.conf

ARG APP_ENV=prod
ARG APP_DEBUG=0
ARG APP_SECRET=build-time-placeholder
ARG LOG_LEVEL=info
ARG DEFAULT_URI=http://localhost

RUN APP_ENV=${APP_ENV} APP_DEBUG=${APP_DEBUG} APP_SECRET=${APP_SECRET} LOG_LEVEL=${LOG_LEVEL} DEFAULT_URI=${DEFAULT_URI} php bin/console cache:warmup \
    && chown -R www-data:www-data /var/www/html/var

# ---- Development stage (extends prod with all dev tooling) ----
FROM prod AS dev

COPY --from=vendor-dev /var/www/html/vendor ./vendor
RUN composer dump-autoload \
    && chown -R www-data:www-data /var/www/html
