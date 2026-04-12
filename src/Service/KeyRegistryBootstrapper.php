<?php

declare(strict_types=1);

namespace App\Service;

use App\Backend\BackendFactory;
use App\Config\AgentConfig;
use Psr\Log\LoggerInterface;

final class KeyRegistryBootstrapper
{
    public function __construct(
        private readonly BackendFactory $backendFactory,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Creates a populated KeyRegistry from configuration.
     */
    public function createRegistry(AgentConfig $config): KeyRegistry
    {
        $registry = new KeyRegistry($this->logger);
        $this->bootstrap($config, $registry);

        return $registry;
    }

    /**
     * Populates the KeyRegistry from config by creating backend instances.
     */
    public function bootstrap(AgentConfig $config, KeyRegistry $registry): void
    {
        $backendsByName = [];
        foreach ($config->backends as $backend) {
            $backendsByName[$backend->name] = $backend;
        }

        foreach ($config->keys as $key) {
            foreach ($key->signingBackends as $backendName) {
                $backendConfig  = $backendsByName[$backendName];
                $signingBackend = $this->backendFactory->createSigningBackend($backendConfig);
                $registry->registerSigningBackend($key->name, $signingBackend);
                $this->logger->info('Registered signing backend', [
                    'key' => $key->name,
                    'backend' => $backendName,
                    'type' => $backendConfig->type,
                ]);
            }

            foreach ($key->decryptionBackends as $backendName) {
                $backendConfig     = $backendsByName[$backendName];
                $decryptionBackend = $this->backendFactory->createDecryptionBackend($backendConfig);
                $registry->registerDecryptionBackend($key->name, $decryptionBackend);
                $this->logger->info('Registered decryption backend', [
                    'key' => $key->name,
                    'backend' => $backendName,
                    'type' => $backendConfig->type,
                ]);
            }
        }
    }
}
