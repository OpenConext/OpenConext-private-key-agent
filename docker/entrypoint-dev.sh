#!/bin/sh
set -e

if [ "${APP_ENV:-dev}" != "prod" ]; then
    composer install --no-interaction
fi

exec /entrypoint.sh "$@"
