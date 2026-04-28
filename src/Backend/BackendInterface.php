<?php

declare(strict_types=1);

namespace App\Backend;

interface BackendInterface
{
    /**
     * Returns the backend group name (as configured in YAML).
     */
    public function getName(): string;

    /**
     * Returns true if the backend can perform operations.
     */
    public function isHealthy(): bool;

    /**
     * Returns SHA-256 fingerprint of the public key in hex.
     * Used for key equivalence checks across backends.
     */
    public function getPublicKeyFingerprint(): string;
}
