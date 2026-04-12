<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\ClientConfig;
use App\Exception\AuthenticationException;

interface AuthenticatorInterface
{
    /**
     * Authenticates a bearer token and returns the matching client config.
     *
     * @throws AuthenticationException If no client matches the token.
     */
    public function authenticate(string $token): ClientConfig;
}
