<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Service;

use OpenConext\PrivateKeyAgent\Backend\OpenSslBackend;
use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use Psr\Log\LoggerInterface;

final class KeyRegistryBootstrapper
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {
    }

    public function createRegistry(AgentConfig $config): KeyRegistry
    {
        $registry = new KeyRegistry();
        $this->bootstrap($config, $registry);

        return $registry;
    }

    private function bootstrap(AgentConfig $config, KeyRegistry $registry): void
    {
        foreach ($config->keys as $key) {
            $backend = new OpenSslBackend($key->name, $key->keyPath);
            $registry->register($key->name, $backend, $key->operations);
            $this->logger->info('Registered key', [
                'key'        => $key->name,
                'operations' => $key->operations,
            ]);
        }
    }
}
