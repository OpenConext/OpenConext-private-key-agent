#!/bin/sh
set -e

composer install --no-interaction

if [ $# -gt 0 ]; then
    exec "$@"
else
    exec apache2-foreground
fi
