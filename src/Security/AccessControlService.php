<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\ClientConfig;
use App\Exception\AccessDeniedException;

use function in_array;
use function sprintf;

final class AccessControlService implements AccessControlInterface
{
    /**
     * Checks whether a client is allowed to access a given key.
     *
     * @throws AccessDeniedException If the client is not allowed to access the key.
     */
    public function checkAccess(ClientConfig $client, string $keyName): void
    {
        if (in_array('*', $client->allowedKeys, true)) {
            return;
        }

        if (! in_array($keyName, $client->allowedKeys, true)) {
            throw new AccessDeniedException(sprintf(
                'Client "%s" is not allowed to access key "%s"',
                $client->name,
                $keyName,
            ));
        }
    }
}
