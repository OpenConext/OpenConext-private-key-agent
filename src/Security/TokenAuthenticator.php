<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;

use function hash_equals;

final class TokenAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private readonly AgentConfig $config,
    ) {
    }

    /**
     * Authenticates a bearer token and returns the matching client config.
     * Uses hash_equals() for timing-safe comparison.
     *
     * @throws AuthenticationException If no client matches the token.
     */
    public function authenticate(string $token): ClientConfig
    {
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
