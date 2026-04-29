#!/bin/sh
set -e

if [ "${APP_ENV:-dev}" != "prod" ]; then
    composer install --no-interaction
fi

if [ $# -gt 0 ]; then
    exec "$@"
else
    exec apache2-foreground
fi
