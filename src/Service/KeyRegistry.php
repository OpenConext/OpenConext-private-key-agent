<?php

declare(strict_types=1);

namespace App\Service;

use App\Backend\BackendInterface;
use App\Backend\DecryptionBackendInterface;
use App\Backend\SigningBackendInterface;
use App\Exception\KeyNotFoundException;

use function array_values;
use function in_array;
use function sprintf;

final class KeyRegistry implements KeyRegistryInterface
{
    /** @var array<string, SigningBackendInterface&DecryptionBackendInterface> */
    private array $backends = [];

    /** @var array<string, list<string>> */
    private array $operations = [];

    /** @param list<string> $operations */
    public function register(string $keyName, SigningBackendInterface&DecryptionBackendInterface $backend, array $operations): void
    {
        $this->backends[$keyName]   = $backend;
        $this->operations[$keyName] = $operations;
    }

    public function getSigningBackend(string $keyName): SigningBackendInterface
    {
        if (! isset($this->backends[$keyName]) || ! in_array('sign', $this->operations[$keyName], true)) {
            throw new KeyNotFoundException(sprintf('Key "%s" not found or does not permit signing', $keyName));
        }

        return $this->backends[$keyName];
    }

    public function getDecryptionBackend(string $keyName): DecryptionBackendInterface
    {
        if (! isset($this->backends[$keyName]) || ! in_array('decrypt', $this->operations[$keyName], true)) {
            throw new KeyNotFoundException(sprintf('Key "%s" not found or does not permit decryption', $keyName));
        }

        return $this->backends[$keyName];
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
