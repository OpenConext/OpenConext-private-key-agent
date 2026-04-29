<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;
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
