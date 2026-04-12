<?php

declare(strict_types=1);

namespace App\Config;

final readonly class ClientConfig
{
    /**
     * @param string       $name        Human-readable client name (for logging)
     * @param string       $token       Bearer token (compared with hash_equals)
     * @param list<string> $allowedKeys Key names this client may access
     */
    public function __construct(
        public string $name,
        public string $token,
        public array $allowedKeys,
    ) {
    }
}
