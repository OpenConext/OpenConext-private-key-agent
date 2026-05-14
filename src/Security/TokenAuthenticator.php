<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Security;

use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Request;

use function hash_equals;
use function str_starts_with;
use function substr;

final class TokenAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private readonly AgentConfig $config,
    ) {
    }

    /**
     * Extracts and authenticates the bearer token from an HTTP request.
     * Uses hash_equals() for timing-safe comparison.
     *
     * On success: returns the matching ClientConfig.
     * On failure: throws AuthenticationException (401).
     *
     * @throws AuthenticationException If the Authorization header is missing or the token is invalid.
     */
    public function authenticate(Request $request): ClientConfig
    {
        $header = $request->headers->get('Authorization', '');
        $token  = str_starts_with($header, 'Bearer ') ? substr($header, 7) : '';

        if ($token === '') {
            throw new AuthenticationException('Missing bearer token');
        }

        foreach ($this->config->clients as $client) {
            if (hash_equals($client->token, $token)) {
                return $client;
            }
        }

        throw new AuthenticationException('Invalid bearer token');
    }
}
