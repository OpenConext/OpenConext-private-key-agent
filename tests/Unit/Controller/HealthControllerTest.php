<?php

declare(strict_types=1);

namespace App\Tests\Unit\Controller;

use App\Backend\DecryptionBackendInterface;
use App\Backend\SigningBackendInterface;
use App\Controller\HealthController;
use App\Service\KeyRegistry;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

use function json_decode;

class HealthControllerTest extends TestCase
{
    public function testHealthReturns200WhenNoBackendsRegistered(): void
    {
        $registry   = new KeyRegistry(new NullLogger());
        $controller = new HealthController($registry);

        $response = $controller->health();

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
    }

    public function testHealthReturns200WhenAllBackendsHealthy(): void
    {
        $backend = $this->createMock(SigningBackendInterface::class);
        $backend->method('isHealthy')->willReturn(true);
        $backend->method('getName')->willReturn('openssl-signing');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('my-key', $backend);
        $controller = new HealthController($registry);

        $response = $controller->health();

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
    }

    public function testHealthReturns503WhenAnyBackendUnhealthy(): void
    {
        $healthy = $this->createMock(SigningBackendInterface::class);
        $healthy->method('isHealthy')->willReturn(true);
        $healthy->method('getName')->willReturn('openssl-signing');

        $unhealthy = $this->createMock(DecryptionBackendInterface::class);
        $unhealthy->method('isHealthy')->willReturn(false);
        $unhealthy->method('getName')->willReturn('backend-a');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('key-a', $healthy);
        $registry->registerDecryptionBackend('key-b', $unhealthy);
        $controller = new HealthController($registry);

        $response = $controller->health();

        $this->assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(503, $body['status']);
        $this->assertSame('server_error', $body['error']);
        $this->assertContains('backend-a', $body['unhealthy_backends']);
        $this->assertNotContains('openssl-signing', $body['unhealthy_backends']);
    }

    public function testHealthUnhealthyBackendNamesAreDeduplicated(): void
    {
        // Same named backend registered under two keys, both unhealthy
        $backend1 = $this->createMock(SigningBackendInterface::class);
        $backend1->method('isHealthy')->willReturn(false);
        $backend1->method('getName')->willReturn('backend-a');

        $backend2 = $this->createMock(SigningBackendInterface::class);
        $backend2->method('isHealthy')->willReturn(false);
        $backend2->method('getName')->willReturn('backend-a');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('key-a', $backend1);
        $registry->registerSigningBackend('key-b', $backend2);
        $controller = new HealthController($registry);

        $response = $controller->health();

        $this->assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(['backend-a'], $body['unhealthy_backends']);
    }

    public function testBackendHealthReturns200ForHealthyBackend(): void
    {
        $backend = $this->createMock(SigningBackendInterface::class);
        $backend->method('isHealthy')->willReturn(true);
        $backend->method('getName')->willReturn('openssl-signing');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('my-key', $backend);
        $controller = new HealthController($registry);

        $response = $controller->backendHealth('openssl-signing');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
        $this->assertSame('openssl-signing', $body['backend_name']);
    }

    public function testBackendHealthReturns503WhenAnyInstanceUnhealthy(): void
    {
        // Same backend name used for signing + decryption; decryption instance is unhealthy
        $signingInstance = $this->createMock(SigningBackendInterface::class);
        $signingInstance->method('isHealthy')->willReturn(true);
        $signingInstance->method('getName')->willReturn('backend-a');

        $decryptionInstance = $this->createMock(DecryptionBackendInterface::class);
        $decryptionInstance->method('isHealthy')->willReturn(false);
        $decryptionInstance->method('getName')->willReturn('backend-a');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('key-b', $signingInstance);
        $registry->registerDecryptionBackend('key-b', $decryptionInstance);
        $controller = new HealthController($registry);

        $response = $controller->backendHealth('backend-a');

        $this->assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(503, $body['status']);
        $this->assertSame('server_error', $body['error']);
        $this->assertSame('backend-a', $body['backend_name']);
    }

    public function testBackendHealthReturns503WhenSameNameAcrossMultipleKeysUnhealthy(): void
    {
        $backend1 = $this->createMock(SigningBackendInterface::class);
        $backend1->method('isHealthy')->willReturn(true);
        $backend1->method('getName')->willReturn('openssl-signing');

        $backend2 = $this->createMock(SigningBackendInterface::class);
        $backend2->method('isHealthy')->willReturn(false);
        $backend2->method('getName')->willReturn('openssl-signing');

        $registry = new KeyRegistry(new NullLogger());
        $registry->registerSigningBackend('key-a', $backend1);
        $registry->registerSigningBackend('key-b', $backend2);
        $controller = new HealthController($registry);

        $response = $controller->backendHealth('openssl-signing');

        $this->assertSame(503, $response->getStatusCode());
    }

    public function testBackendHealthReturns404ForUnknownBackend(): void
    {
        $registry   = new KeyRegistry(new NullLogger());
        $controller = new HealthController($registry);

        $response = $controller->backendHealth('no-such-backend');

        $this->assertSame(404, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('not_found', $body['status']);
        $this->assertSame('no-such-backend', $body['backend_name']);
    }
}
