<?php

declare(strict_types=1);

namespace App\Config;

final readonly class BackendGroupConfig
{
    /** @param array<string,string> $environment */
    public function __construct(
        public string $name,
        public string $type,
        public string|null $keyPath = null,
        public string|null $pkcs11Lib = null,
        public int|null $pkcs11Slot = null,
        public string|null $pkcs11Pin = null,
        public string|null $pkcs11KeyLabel = null,
        public string|null $pkcs11KeyId = null,
        public array $environment = [],
    ) {
    }
}
