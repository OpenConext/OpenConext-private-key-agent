<?php

declare(strict_types=1);

namespace App\Config;

final readonly class KeyConfig
{
    /**
     * @param string       $name               Key name used in URL path (e.g. "my-signing-key")
     * @param list<string> $signingBackends    Backend group names for signing
     * @param list<string> $decryptionBackends Backend group names for decryption
     */
    public function __construct(
        public string $name,
        public array $signingBackends = [],
        public array $decryptionBackends = [],
    ) {
    }
}
