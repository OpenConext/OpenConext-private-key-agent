<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Security;

use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Exception\AuthenticationException;
use OpenConext\PrivateKeyAgent\Security\TokenAuthenticator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

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

    public function testAuthenticateWithValidToken(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token-here-must-be-long', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config);
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

        $authenticator = new TokenAuthenticator($config);

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

        $authenticator = new TokenAuthenticator($config);
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

        $authenticator = new TokenAuthenticator($config);
        $request       = Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']);
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateResolvesCorrectClientFromMultipleClients(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'client-a', token: 'token-aaa', allowedKeys: ['key1']),
                new ClientConfig(name: 'client-b', token: 'token-bbb', allowedKeys: ['key2']),
            ],
        );

        $authenticator = new TokenAuthenticator($config);

        $clientB = $authenticator->authenticate($this->makeRequest('token-bbb'));
        $this->assertSame('client-b', $clientB->name);

        $clientA = $authenticator->authenticate($this->makeRequest('token-aaa'));
        $this->assertSame('client-a', $clientA->name);
    }

    public function testRepeatedAuthFailuresAlwaysThrowAuthenticationException(): void
    {
        // Regression test: removing rate limiting must not cause repeated failures to produce
        // anything other than AuthenticationException (no 429 / no Retry-After logic).
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'my-client', token: 'valid-token', allowedKeys: ['key1']),
            ],
        );

        $authenticator = new TokenAuthenticator($config);

        for ($i = 0; $i < 10; $i++) {
            try {
                $authenticator->authenticate($this->makeRequest('wrong-token-' . $i));
                $this->fail('Expected AuthenticationException on attempt ' . $i);
            } catch (AuthenticationException) {
                // Expected: every failure must be AuthenticationException, never anything else
            }
        }

        // After 10 failures the valid token must still work (no lockout state)
        $client = $authenticator->authenticate($this->makeRequest('valid-token'));
        $this->assertSame('my-client', $client->name);
    }
}
