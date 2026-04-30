<?php

declare(strict_types=1);

namespace App\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;
use App\Exception\RateLimitException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

use function hash_equals;
use function str_starts_with;
use function substr;

final class TokenAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private readonly AgentConfig $config,
        private readonly RateLimiterFactoryInterface $authFailureLimiter,
    ) {
    }

    /**
     * Extracts and authenticates the bearer token from an HTTP request.
     * Uses hash_equals() for timing-safe comparison.
     *
     * On success: returns the matching ClientConfig with zero rate-limiter interaction.
     * On failure: records the failure against the caller IP. Throws RateLimitException
     *             (429) once the limit is exceeded, AuthenticationException (401) otherwise.
     *
     * @throws AuthenticationException If the Authorization header is missing or the token is invalid.
     * @throws RateLimitException      If too many authentication failures have occurred.
     */
    public function authenticate(Request $request): ClientConfig
    {
        $header = $request->headers->get('Authorization', '');
        $token  = str_starts_with($header, 'Bearer ') ? substr($header, 7) : '';

        if ($token === '') {
            $this->recordFailure($request, 'Missing bearer token');
        }

        foreach ($this->config->clients as $client) {
            if (hash_equals($client->token, $token)) {
                return $client;
            }
        }

        $this->recordFailure($request, 'Invalid bearer token');
    }

    /**
     * Records an authentication failure for the caller IP. Throws RateLimitException if the
     * sliding window is exhausted, or AuthenticationException to signal a normal 401.
     *
     * @throws RateLimitException
     * @throws AuthenticationException
     */
    private function recordFailure(Request $request, string $message): never
    {
        $ip        = $request->getClientIp() ?? 'unknown';
        $rateLimit = $this->authFailureLimiter->create($ip)->consume(1);

        if (! $rateLimit->isAccepted()) {
            throw new RateLimitException($rateLimit->getRetryAfter());
        }

        throw new AuthenticationException($message);
    }
}
