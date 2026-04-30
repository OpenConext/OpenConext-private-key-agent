#!/bin/sh
set -e

if [ "${APP_ENV:-dev}" != "prod" ]; then
    composer install --prefer-dist --no-progress --no-interaction
fi

exec "$@"
