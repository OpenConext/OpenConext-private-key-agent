<?php

declare(strict_types=1);

namespace App\Tests\Unit\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;
use App\Exception\RateLimitException;
use App\Security\TokenAuthenticator;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\LimiterInterface;
use Symfony\Component\RateLimiter\RateLimit;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

class TokenAuthenticatorTest extends TestCase
{
    private function makeRequest(string $token): Request
    {
        $request = Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']);
        if ($token !== '') {
            $request->headers->set('Authorization', 'Bearer ' . $token);
        }

        return $request;
    }

    /** Returns a RateLimiterFactoryInterface mock that always accepts (token not exhausted). */
    private function makeAcceptingLimiter(): RateLimiterFactoryInterface
    {
        $rateLimit = $this->createMock(RateLimit::class);
        $rateLimit->method('isAccepted')->willReturn(true);

        $limiter = $this->createMock(LimiterInterface::class);
        $limiter->method('consume')->willReturn($rateLimit);

        $factory = $this->createMock(RateLimiterFactoryInterface::class);
        $factory->method('create')->willReturn($limiter);

        return $factory;
    }

    /** Returns a RateLimiterFactoryInterface mock that rejects (limit exhausted). */
    private function makeExhaustedLimiter(): RateLimiterFactoryInterface
    {
        $retryAfter = new DateTimeImmutable('+60 seconds');

        $rateLimit = $this->createMock(RateLimit::class);
        $rateLimit->method('isAccepted')->willReturn(false);
        $rateLimit->method('getRetryAfter')->willReturn($retryAfter);

        $limiter = $this->createMock(LimiterInterface::class);
        $limiter->method('consume')->willReturn($rateLimit);

        $factory = $this->createMock(RateLimiterFactoryInterface::class);
        $factory->method('create')->willReturn($limiter);

        return $factory;
    }

    public function testAuthenticateWithValidToken(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token-here-must-be-long', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());
        $client        = $authenticator->authenticate($this->makeRequest('valid-token-here-must-be-long'));

        $this->assertSame('my-client', $client->name);
        $this->assertSame(['key1'], $client->allowedKeys);
    }

    public function testAuthenticateWithInvalidTokenThrows(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($this->makeRequest('wrong-token'));
    }

    public function testAuthenticateWithMissingAuthorizationHeaderThrows(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());
        $request       = Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateWithNonBearerSchemeThrows(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());
        $request       = Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']);
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateUsesTimingSafeComparison(): void
    {
        // Verifies the authenticator works with multiple clients and picks the right one
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'client-a', token: 'token-aaa', allowedKeys: ['key1']),
                new ClientConfig(name: 'client-b', token: 'token-bbb', allowedKeys: ['key2']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());

        $clientB = $authenticator->authenticate($this->makeRequest('token-bbb'));
        $this->assertSame('client-b', $clientB->name);

        $clientA = $authenticator->authenticate($this->makeRequest('token-aaa'));
        $this->assertSame('client-a', $clientA->name);
    }

    public function testRateLimitNotYetExhaustedThrowsAuthenticationException(): void
    {
        // Under the limit: still throws AuthenticationException (401), not RateLimitException (429)
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($this->makeRequest('wrong-token'));
    }

    public function testRateLimitExhaustedThrowsRateLimitException(): void
    {
        // Limit exhausted: throws RateLimitException (429) instead of AuthenticationException
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeExhaustedLimiter());

        $this->expectException(RateLimitException::class);
        $authenticator->authenticate($this->makeRequest('wrong-token'));
    }

    public function testRateLimitExhaustedOnMissingTokenThrowsRateLimitException(): void
    {
        // Missing token also triggers rate limiter
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config, $this->makeExhaustedLimiter());
        $request       = Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']);

        $this->expectException(RateLimitException::class);
        $authenticator->authenticate($request);
    }

    public function testValidTokenDoesNotConsumeLimiterToken(): void
    {
        // Success path: the limiter's consume() must NOT be called
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $limiter = $this->createMock(LimiterInterface::class);
        $limiter->expects($this->never())->method('consume');

        $factory = $this->createMock(RateLimiterFactoryInterface::class);
        $factory->method('create')->willReturn($limiter);

        $authenticator = new TokenAuthenticator($config, $factory);
        $authenticator->authenticate($this->makeRequest('valid-token'));
    }
}
