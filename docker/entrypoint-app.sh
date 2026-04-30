#!/bin/sh
set -e

if [ "${APP_ENV:-dev}" != "prod" ]; then
    composer install --prefer-dist --no-progress --no-interaction
fi

if [ $# -gt 0 ]; then
    exec "$@"
fi

exec /entrypoint.sh sh -c 'php bin/console cache:warmup --no-interaction && chown -R www-data:www-data /var/www/html/var && exec apache2-foreground'
