FROM dunglas/frankenphp:1-php8.5-bookworm AS base

# Patch script for php-pkcs11: see docker/pkcs11-zts-patch.pl for full explanation.
COPY docker/pkcs11-zts-patch.pl /tmp/pkcs11-zts-patch.pl

# Build gamringer/php-pkcs11 from source with thread-safety patches for FrankenPHP
# ZTS worker mode.  See docker/pkcs11-zts-patch.pl for a full explanation of each patch.
RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS git \
    && git clone --depth=1 --branch v1.1.3 \
        https://github.com/gamringer/php-pkcs11 /tmp/php-pkcs11 \
    && perl /tmp/pkcs11-zts-patch.pl /tmp/php-pkcs11/pkcs11module.c \
    && grep -q 'pkcs11_cinit_mutex' /tmp/php-pkcs11/pkcs11module.c \
        || { echo "ERROR: pkcs11 ZTS patch was not applied"; exit 1; } \
    && cd /tmp/php-pkcs11 && phpize && ./configure && make && make install \
    && docker-php-ext-enable pkcs11 \
    && rm -rf /tmp/php-pkcs11 \
    && apt-get purge -y $PHPIZE_DEPS git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# ---- Production stage ----
FROM base AS prod

COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

COPY docker/app.ini /usr/local/etc/php/conf.d/app.ini

RUN APP_ENV=prod APP_DEBUG=0 APP_SECRET=build-time-secret LOG_LEVEL=info php bin/console cache:warmup \
    && chown -R www-data:www-data /app/var

# ---- Development stage (extends prod with dev tooling) ----
FROM prod AS dev

RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*

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
