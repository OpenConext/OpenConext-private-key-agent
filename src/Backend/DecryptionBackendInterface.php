<?php

declare(strict_types=1);

namespace App\Backend;

use App\Exception\BackendException;
use App\Exception\InvalidRequestException;

interface DecryptionBackendInterface extends BackendInterface
{
    /**
     * Decrypts ciphertext using the configured private key.
     *
     * @param string $ciphertext Raw ciphertext bytes (not base64)
     * @param string $algorithm  One of: rsa-pkcs1-v1_5, rsa-pkcs1-oaep-mgf1-sha1,
     *                           rsa-pkcs1-oaep-mgf1-sha224, rsa-pkcs1-oaep-mgf1-sha256,
     *                           rsa-pkcs1-oaep-mgf1-sha384, rsa-pkcs1-oaep-mgf1-sha512
     *
     * @return string Raw decrypted bytes (not base64)
     *
     * @throws InvalidRequestException If ciphertext length doesn't match modulus.
     * @throws BackendException If the decryption operation fails.
     */
    public function decrypt(string $ciphertext, string $algorithm): string;
}
