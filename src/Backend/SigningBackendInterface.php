<?php

declare(strict_types=1);

namespace App\Backend;

use App\Exception\BackendException;
use App\Exception\InvalidRequestException;

interface SigningBackendInterface extends BackendInterface
{
    /**
     * Signs a hash using the configured private key.
     *
     * @param string $hash      Raw hash bytes (not base64)
     * @param string $algorithm One of: rsa-pkcs1-v1_5-sha1, rsa-pkcs1-v1_5-sha256,
     *                          rsa-pkcs1-v1_5-sha384, rsa-pkcs1-v1_5-sha512
     *
     * @return string Raw signature bytes (not base64)
     *
     * @throws InvalidRequestException If the hash length is wrong for the algorithm.
     * @throws BackendException If the signing operation fails.
     */
    public function sign(string $hash, string $algorithm): string;
}
