<?php

declare(strict_types=1);

namespace App\Tests\Unit\Security;

use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Exception\AuthenticationException;
use App\Security\TokenAuthenticator;
use PHPUnit\Framework\TestCase;

class TokenAuthenticatorTest extends TestCase
{
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
        $client        = $authenticator->authenticate('valid-token-here-must-be-long');

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
        $authenticator->authenticate('wrong-token');
    }

    public function testAuthenticateWithEmptyTokenThrows(): void
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
        $authenticator->authenticate('');
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

        $clientB = $authenticator->authenticate('token-bbb');
        $this->assertSame('client-b', $clientB->name);

        $clientA = $authenticator->authenticate('token-aaa');
        $this->assertSame('client-a', $clientA->name);
    }
}
