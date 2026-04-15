<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

use function sprintf;

final class BackendFactory
{
    /** @param iterable<BackendTypeFactoryInterface> $typeFactories */
    public function __construct(
        #[AutowireIterator('app.backend_type_factory')]
        private readonly iterable $typeFactories,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function createSigningBackend(BackendGroupConfig $config): SigningBackendInterface
    {
        $this->logger->info('Creating signing backend {type}', ['type' => $config->type] );
        return $this->resolveFactory($config->type)->createSigningBackend($config, $this->logger);
    }

    public function createDecryptionBackend(BackendGroupConfig $config): DecryptionBackendInterface
    {
        $this->logger->info('Creating decryption backend {type}', ['type' => $config->type] );
        return $this->resolveFactory($config->type)->createDecryptionBackend($config, $this->logger);
    }

    private function resolveFactory(string $type): BackendTypeFactoryInterface
    {
        foreach ($this->typeFactories as $factory) {
            if ($factory->supports($type)) {

                return $factory;
            }
        }

        throw new BackendException(sprintf('Unknown backend type "%s"', $type));
    }
}