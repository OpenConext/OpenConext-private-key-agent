<?php

declare(strict_types=1);

namespace App\Backend;

interface BackendInterface
{
    /**
     * Returns the key name (as configured in YAML).
     */
    public function getName(): string;

    /**
     * Returns true if the backend can perform operations.
     */
    public function isHealthy(): bool;
}
