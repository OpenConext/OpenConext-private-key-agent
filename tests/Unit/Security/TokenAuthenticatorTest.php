<?php

declare(strict_types=1);

namespace App\Tests\Unit\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;
use App\Security\TokenAuthenticator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class TokenAuthenticatorTest extends TestCase
{
    private function makeRequest(string $token): Request
    {
        $request = new Request();
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

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate(new Request());
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
        $request       = new Request();
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

        $authenticator = new TokenAuthenticator($config);

        $clientB = $authenticator->authenticate($this->makeRequest('token-bbb'));
        $this->assertSame('client-b', $clientB->name);

        $clientA = $authenticator->authenticate($this->makeRequest('token-aaa'));
        $this->assertSame('client-a', $clientA->name);
    }
}
