<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

use function sprintf;

final class BackendFactory
{
    /** @param iterable<BackendTypeFactoryInterface> $typeFactories */
    public function __construct(
        #[AutowireIterator('app.backend_type_factory')]
        private readonly iterable $typeFactories,
    ) {
    }

    public function createSigningBackend(BackendGroupConfig $config): SigningBackendInterface
    {
        return $this->resolveFactory($config->type)->createSigningBackend($config);
    }

    public function createDecryptionBackend(BackendGroupConfig $config): DecryptionBackendInterface
    {
        return $this->resolveFactory($config->type)->createDecryptionBackend($config);
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
