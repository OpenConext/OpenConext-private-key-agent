<?php

declare(strict_types=1);

namespace App\Config;

final readonly class KeyConfig
{
    /**
     * @param string                 $name       Key name used in URL path (e.g. "my-signing-key")
     * @param string                 $keyPath    Path to the PEM private key file
     * @param list<'sign'|'decrypt'> $operations Permitted operations for this key
     */
    public function __construct(
        public string $name,
        public string $keyPath,
        public array $operations,
    ) {
    }
}
