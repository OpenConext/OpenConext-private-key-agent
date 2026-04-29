<?php

declare(strict_types=1);

namespace App\Tests\Unit\Controller;

use App\Backend\BackendInterface;
use App\Controller\HealthController;
use App\Service\KeyRegistryInterface;
use PHPUnit\Framework\TestCase;

use function json_decode;

class HealthControllerTest extends TestCase
{
    public function testHealthReturns200WhenNoBackendsRegistered(): void
    {
        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('getAllBackends')->willReturn([]);

        $controller = new HealthController($registry);
        $response   = $controller->health();

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
    }

    public function testHealthReturns200WhenAllBackendsHealthy(): void
    {
        $backend = $this->createMock(BackendInterface::class);
        $backend->method('isHealthy')->willReturn(true);
        $backend->method('getName')->willReturn('my-key');

        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('getAllBackends')->willReturn([$backend]);

        $controller = new HealthController($registry);
        $response   = $controller->health();

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
    }

    public function testHealthReturns503WhenAnyBackendUnhealthy(): void
    {
        $healthy = $this->createMock(BackendInterface::class);
        $healthy->method('isHealthy')->willReturn(true);
        $healthy->method('getName')->willReturn('healthy-key');

        $unhealthy = $this->createMock(BackendInterface::class);
        $unhealthy->method('isHealthy')->willReturn(false);
        $unhealthy->method('getName')->willReturn('bad-key');

        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('getAllBackends')->willReturn([$healthy, $unhealthy]);

        $controller = new HealthController($registry);
        $response   = $controller->health();

        $this->assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(503, $body['status']);
        $this->assertSame('server_error', $body['error']);
        $this->assertContains('bad-key', $body['unhealthy_keys']);
        $this->assertNotContains('healthy-key', $body['unhealthy_keys']);
    }

    public function testKeyHealthReturns200ForHealthyKey(): void
    {
        $backend = $this->createMock(BackendInterface::class);
        $backend->method('isHealthy')->willReturn(true);

        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('findBackend')->with('my-key')->willReturn($backend);

        $controller = new HealthController($registry);
        $response   = $controller->keyHealth('my-key');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('OK', $body['status']);
        $this->assertSame('my-key', $body['key_name']);
    }

    public function testKeyHealthReturns404ForUnknownKey(): void
    {
        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('findBackend')->with('no-such-key')->willReturn(null);

        $controller = new HealthController($registry);
        $response   = $controller->keyHealth('no-such-key');

        $this->assertSame(404, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('not_found', $body['status']);
        $this->assertSame('no-such-key', $body['key_name']);
    }

    public function testKeyHealthReturns503WhenKeyIsUnhealthy(): void
    {
        $backend = $this->createMock(BackendInterface::class);
        $backend->method('isHealthy')->willReturn(false);

        $registry = $this->createMock(KeyRegistryInterface::class);
        $registry->method('findBackend')->with('bad-key')->willReturn($backend);

        $controller = new HealthController($registry);
        $response   = $controller->keyHealth('bad-key');

        $this->assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(503, $body['status']);
        $this->assertSame('server_error', $body['error']);
        $this->assertSame('bad-key', $body['key_name']);
    }
}
