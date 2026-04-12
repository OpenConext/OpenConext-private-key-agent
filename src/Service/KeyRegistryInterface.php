<?php

declare(strict_types=1);

namespace App\Service;

use App\Backend\BackendInterface;
use App\Backend\DecryptionBackendInterface;
use App\Backend\SigningBackendInterface;
use App\Exception\InvalidRequestException;

interface KeyRegistryInterface
{
    /**
     * Returns the next signing backend for the given key name (round-robin).
     *
     * @throws InvalidRequestException If no signing backend is registered for the key.
     */
    public function getSigningBackend(string $keyName): SigningBackendInterface;

    /**
     * Returns the next decryption backend for the given key name (round-robin).
     *
     * @throws InvalidRequestException If no decryption backend is registered for the key.
     */
    public function getDecryptionBackend(string $keyName): DecryptionBackendInterface;

    /** @return list<string> */
    public function getSigningKeyNames(): array;

    /** @return list<string> */
    public function getDecryptionKeyNames(): array;

    /** @return list<SigningBackendInterface> */
    public function getAllSigningBackends(string $keyName): array;

    /** @return list<DecryptionBackendInterface> */
    public function getAllDecryptionBackends(string $keyName): array;

    /**
     * Returns all registered backend instances, deduplicated by object identity.
     *
     * @return list<BackendInterface>
     */
    public function getAllBackends(): array;

    /**
     * Returns all backend instances whose configured name matches $backendName.
     * Returns an empty list if no backend with that name is registered.
     *
     * @return list<BackendInterface>
     */
    public function getBackendsByName(string $backendName): array;
}
