<?php

declare(strict_types=1);

namespace App\Config;

final readonly class AgentConfig
{
    /**
     * @param string                   $agentName Human-readable name used in WWW-Authenticate realm
     * @param list<BackendGroupConfig> $backends
     * @param list<KeyConfig>          $keys
     * @param list<ClientConfig>       $clients
     */
    public function __construct(
        public string $agentName,
        public array $backends,
        public array $keys,
        public array $clients,
    ) {
    }
}
