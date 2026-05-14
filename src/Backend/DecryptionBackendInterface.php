<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Backend;

use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

interface DecryptionBackendInterface extends BackendInterface
{
    /**
     * Decrypts ciphertext using the configured private key.
     *
     * @see \OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm for valid algorithm identifiers.
     *
     * @param string $ciphertext Raw ciphertext bytes (not base64)
     * @param string $algorithm  Decryption algorithm identifier.
     *
     * @return string Raw decrypted bytes (not base64)
     *
     * @throws InvalidRequestException If ciphertext length doesn't match modulus.
     * @throws BackendException If the decryption operation fails.
     */
    public function decrypt(string $ciphertext, string $algorithm): string;
}
