<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Backend;

use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

interface DecryptionBackendInterface extends BackendInterface
{
    /**
     * Decrypts ciphertext using the configured private key.
     *
     * @param string              $ciphertext Raw ciphertext bytes (not base64)
     * @param EncryptionAlgorithm $algorithm  Decryption algorithm.
     *
     * @return string Raw decrypted bytes (not base64)
     *
     * @throws InvalidRequestException If ciphertext length doesn't match modulus.
     * @throws BackendException If the decryption operation fails.
     */
    public function decrypt(string $ciphertext, EncryptionAlgorithm $algorithm): string;
}
