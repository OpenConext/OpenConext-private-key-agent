<?php

declare(strict_types=1);

namespace App\Config;

final readonly class BackendGroupConfig
{
    public function __construct(
        public string $name,
        public string $type,
        public string|null $keyPath = null,
    ) {
    }
}
