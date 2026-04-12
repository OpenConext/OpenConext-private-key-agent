FROM php:8.5-fpm-alpine AS base

# Install gamringer/php-pkcs11 (PECL extension name: pkcs11)
RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS \
    && pecl install pkcs11 \
    && docker-php-ext-enable pkcs11 \
    && apk del .build-deps \
    && rm -rf /tmp/pear /var/cache/apk/*

# php_cli_get_shell_callbacks is a CLI-SAPI-only function. PHP-FPM does not
# define it, but musl libc's RTLD_NOW resolves ALL pending lazy relocations
# across every loaded DSO when any dlopen(RTLD_NOW) is called. This catches
# a lazy reference to php_cli_get_shell_callbacks that was deferred during
# PHP's readline module initialisation in FPM, causing dlopen to fail with
# "Symbol not found: php_cli_get_shell_callbacks". The stub below satisfies
# that reference so that PKCS#11 library loading succeeds in FPM workers.
RUN apk add --no-cache --virtual .stub-build gcc musl-dev \
    && printf '#include <stddef.h>\nvoid *php_cli_get_shell_callbacks(void) { return NULL; }\n' \
        > /tmp/stub.c \
    && gcc -shared -fPIC -nostartfiles -o /usr/local/lib/php_cli_stub.so /tmp/stub.c \
    && rm /tmp/stub.c \
    && apk del .stub-build

ENV LD_PRELOAD=/usr/local/lib/php_cli_stub.so

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# ---- Production stage ----
FROM base AS prod

COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-app.conf
COPY docker/app.ini /usr/local/etc/php/conf.d/app.ini

RUN APP_ENV=prod APP_DEBUG=0 APP_SECRET=build-time-secret php bin/console cache:warmup \
    && chown -R www-data:www-data /app/var

USER www-data

EXPOSE 9000

# ---- Development stage (extends prod with dev tooling) ----
FROM prod AS dev

USER root

RUN apk add --no-cache softhsm opensc

ENV SOFTHSM2_CONF=/etc/softhsm2.conf

# Initialise a SoftHSM2 test token and generate an RSA-2048 key pair so that
# the PKCS#11 integration tests run (not just skip).
RUN mkdir -p /var/lib/softhsm/tokens \
    && printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
        > /etc/softhsm2.conf \
    && softhsm2-util --init-token --slot 0 \
        --label "test-token" --pin 1234 --so-pin 5678 \
    && pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
        --login --pin 1234 \
        --slot-index 0 \
        --keypairgen --key-type rsa:2048 \
        --label "test-signing-key" --id 01 \
    && chown -R www-data:www-data /var/lib/softhsm

RUN composer install --no-scripts --no-autoloader --prefer-dist \
    && composer dump-autoload \
    && chown www-data:www-data /app

USER www-data
