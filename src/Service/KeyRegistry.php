<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Service;

use OpenConext\PrivateKeyAgent\Backend\BackendInterface;
use OpenConext\PrivateKeyAgent\Backend\DecryptionBackendInterface;
use OpenConext\PrivateKeyAgent\Backend\SigningBackendInterface;
use OpenConext\PrivateKeyAgent\Exception\KeyNotFoundException;

use function array_values;
use function in_array;
use function sprintf;

final class KeyRegistry implements KeyRegistryInterface
{
    /** @var array<string, BackendInterface> */
    private array $backends = [];

    /** @var array<string, list<string>> */
    private array $operations = [];

    /** @param list<string> $operations */
    public function register(string $keyName, BackendInterface $backend, array $operations): void
    {
        $this->backends[$keyName]   = $backend;
        $this->operations[$keyName] = $operations;
    }

    public function getSigningBackend(string $keyName): SigningBackendInterface
    {
        $backend = $this->backends[$keyName] ?? null;
        if ($backend === null || ! in_array('sign', $this->operations[$keyName], true)) {
            throw new KeyNotFoundException(sprintf('Key "%s" not found or does not permit signing', $keyName));
        }

        if (! $backend instanceof SigningBackendInterface) {
            throw new KeyNotFoundException(sprintf('Key "%s" backend does not support signing', $keyName));
        }

        return $backend;
    }

    public function getDecryptionBackend(string $keyName): DecryptionBackendInterface
    {
        $backend = $this->backends[$keyName] ?? null;
        if ($backend === null || ! in_array('decrypt', $this->operations[$keyName], true)) {
            throw new KeyNotFoundException(sprintf('Key "%s" not found or does not permit decryption', $keyName));
        }

        if (! $backend instanceof DecryptionBackendInterface) {
            throw new KeyNotFoundException(sprintf('Key "%s" backend does not support decryption', $keyName));
        }

        return $backend;
    }

    /** @return list<BackendInterface> */
    public function getAllBackends(): array
    {
        return array_values($this->backends);
    }

    public function findBackend(string $keyName): BackendInterface|null
    {
        return $this->backends[$keyName] ?? null;
    }
}
