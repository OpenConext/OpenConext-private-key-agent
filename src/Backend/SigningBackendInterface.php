<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Backend;

use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

interface SigningBackendInterface extends BackendInterface
{
    /**
     * Signs a hash using the configured private key.
     *
     * @see \OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm for valid algorithm identifiers.
     *
     * @param string $hash      Raw hash bytes (not base64)
     * @param string $algorithm Signing algorithm identifier.
     *
     * @return string Raw signature bytes (not base64)
     *
     * @throws InvalidRequestException If the hash length is wrong for the algorithm.
     * @throws BackendException If the signing operation fails.
     */
    public function sign(string $hash, string $algorithm): string;
}
