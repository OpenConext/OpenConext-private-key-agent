<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\ClientConfig;
use App\Exception\AccessDeniedException;

interface AccessControlInterface
{
    /**
     * Checks whether a client is allowed to access a given key.
     *
     * @throws AccessDeniedException If the client is not allowed to access the key.
     */
    public function checkAccess(ClientConfig $client, string $keyName): void;
}
