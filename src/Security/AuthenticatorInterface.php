<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Security;

use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Request;

interface AuthenticatorInterface
{
    /**
     * Extracts and authenticates the bearer token from an HTTP request.
     *
     * @throws AuthenticationException If the Authorization header is missing or the token is invalid.
     */
    public function authenticate(Request $request): ClientConfig;
}
