<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Service;

use OpenConext\PrivateKeyAgent\Backend\BackendInterface;
use OpenConext\PrivateKeyAgent\Backend\DecryptionBackendInterface;
use OpenConext\PrivateKeyAgent\Backend\SigningBackendInterface;
use OpenConext\PrivateKeyAgent\Exception\KeyNotFoundException;

interface KeyRegistryInterface
{
    /**
     * Returns the signing backend for the given key name.
     *
     * @throws KeyNotFoundException If the key does not exist or does not permit signing.
     */
    public function getSigningBackend(string $keyName): SigningBackendInterface;

    /**
     * Returns the decryption backend for the given key name.
     *
     * @throws KeyNotFoundException If the key does not exist or does not permit decryption.
     */
    public function getDecryptionBackend(string $keyName): DecryptionBackendInterface;

    /**
     * Returns all registered backends.
     *
     * @return list<BackendInterface>
     */
    public function getAllBackends(): array;

    /**
     * Returns the backend for the given key name, or null if not found.
     */
    public function findBackend(string $keyName): BackendInterface|null;
}
