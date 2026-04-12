<?php

declare(strict_types=1);

namespace App\Config;

use App\Exception\BackendException;

final class ConfigProvider
{
    private AgentConfig|null $config = null;

    public function __construct(
        private readonly string $configPath,
    ) {
    }

    public function getConfig(): AgentConfig
    {
        if ($this->config === null) {
            if ($this->configPath === '') {
                throw new BackendException('Config path is not set');
            }

            $this->config = ConfigLoader::load($this->configPath);
        }

        return $this->config;
    }
}
