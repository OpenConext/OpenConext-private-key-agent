<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Config;

final readonly class AgentConfig
{
    /**
     * @param string             $agentName Human-readable name used in WWW-Authenticate realm
     * @param list<KeyConfig>    $keys
     * @param list<ClientConfig> $clients
     */
    public function __construct(
        public string $agentName,
        public array $keys,
        public array $clients,
    ) {
    }
}
