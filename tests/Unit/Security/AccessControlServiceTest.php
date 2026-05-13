<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Security;

use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Exception\AccessDeniedException;
use OpenConext\PrivateKeyAgent\Security\AccessControlService;
use PHPUnit\Framework\TestCase;

class AccessControlServiceTest extends TestCase
{
    public function testCheckAccessAllowed(): void
    {
        $this->expectNotToPerformAssertions();
        $client  = new ClientConfig(name: 'client-a', token: 'tok', allowedKeys: ['key1', 'key2']);
        $service = new AccessControlService();

        $service->checkAccess($client, 'key1');
    }

    public function testCheckAccessDenied(): void
    {
        $client  = new ClientConfig(name: 'client-a', token: 'tok', allowedKeys: ['key1']);
        $service = new AccessControlService();

        $this->expectException(AccessDeniedException::class);
        $service->checkAccess($client, 'key-not-allowed');
    }

    public function testCheckAccessWithWildcard(): void
    {
        $this->expectNotToPerformAssertions();
        $client  = new ClientConfig(name: 'admin', token: 'tok', allowedKeys: ['*']);
        $service = new AccessControlService();

        $service->checkAccess($client, 'any-key-name');
    }
}
