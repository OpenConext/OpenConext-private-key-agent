<?php

declare(strict_types=1);

namespace App\Tests\Unit\Service;

use App\Backend\DecryptionBackendInterface;
use App\Backend\SigningBackendInterface;
use App\Exception\InvalidConfigurationException;
use App\Exception\InvalidRequestException;
use App\Service\KeyRegistry;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function str_repeat;

class KeyRegistryTest extends TestCase
{
    private function createRegistry(LoggerInterface|null $logger = null): KeyRegistry
    {
        return new KeyRegistry($logger ?? new NullLogger());
    }

    public function testGetSigningBackendReturnsRegisteredBackend(): void
    {
        $backend = $this->createMock(SigningBackendInterface::class);
        $backend->method('getName')->willReturn('soft-key-1');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('my-key', $backend);

        $result = $registry->getSigningBackend('my-key');
        $this->assertSame($backend, $result);
    }

    public function testGetSigningBackendThrowsOnUnknownKey(): void
    {
        $registry = $this->createRegistry();

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('no-such-key');
        $registry->getSigningBackend('no-such-key');
    }

    public function testGetDecryptionBackendReturnsRegisteredBackend(): void
    {
        $backend = $this->createMock(DecryptionBackendInterface::class);
        $backend->method('getName')->willReturn('soft-key-1');

        $registry = $this->createRegistry();
        $registry->registerDecryptionBackend('my-key', $backend);

        $result = $registry->getDecryptionBackend('my-key');
        $this->assertSame($backend, $result);
    }

    public function testGetDecryptionBackendThrowsOnUnknownKey(): void
    {
        $registry = $this->createRegistry();

        $this->expectException(InvalidRequestException::class);
        $registry->getDecryptionBackend('no-such-key');
    }

    public function testRoundRobinSigningBackends(): void
    {
        $backend1 = $this->createMock(SigningBackendInterface::class);
        $backend1->method('getName')->willReturn('b1');
        $backend1->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));
        $backend2 = $this->createMock(SigningBackendInterface::class);
        $backend2->method('getName')->willReturn('b2');
        $backend2->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('my-key', $backend1);
        $registry->registerSigningBackend('my-key', $backend2);

        $first  = $registry->getSigningBackend('my-key');
        $second = $registry->getSigningBackend('my-key');
        $third  = $registry->getSigningBackend('my-key');

        $this->assertNotSame($first, $second);
        $this->assertSame($first, $third);
    }

    public function testRoundRobinDecryptionBackends(): void
    {
        $backend1 = $this->createMock(DecryptionBackendInterface::class);
        $backend1->method('getName')->willReturn('b1');
        $backend1->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));
        $backend2 = $this->createMock(DecryptionBackendInterface::class);
        $backend2->method('getName')->willReturn('b2');
        $backend2->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));

        $registry = $this->createRegistry();
        $registry->registerDecryptionBackend('my-key', $backend1);
        $registry->registerDecryptionBackend('my-key', $backend2);

        $first  = $registry->getDecryptionBackend('my-key');
        $second = $registry->getDecryptionBackend('my-key');
        $third  = $registry->getDecryptionBackend('my-key');

        $this->assertNotSame($first, $second);
        $this->assertSame($first, $third);
    }

    public function testGetSigningKeyNames(): void
    {
        $backend = $this->createMock(SigningBackendInterface::class);

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-a', $backend);
        $registry->registerSigningBackend('key-b', $backend);

        $this->assertEqualsCanonicalizing(['key-a', 'key-b'], $registry->getSigningKeyNames());
    }

    public function testGetDecryptionKeyNames(): void
    {
        $backend = $this->createMock(DecryptionBackendInterface::class);

        $registry = $this->createRegistry();
        $registry->registerDecryptionBackend('key-x', $backend);

        $this->assertSame(['key-x'], $registry->getDecryptionKeyNames());
    }

    public function testGetAllBackendsReturnsAllUniqueInstances(): void
    {
        $s1 = $this->createMock(SigningBackendInterface::class);
        $s1->method('getName')->willReturn('openssl-signing');
        $d1 = $this->createMock(DecryptionBackendInterface::class);
        $d1->method('getName')->willReturn('openssl-decryption');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-a', $s1);
        $registry->registerDecryptionBackend('key-a', $d1);

        $all = $registry->getAllBackends();
        $this->assertCount(2, $all);
        $this->assertContains($s1, $all);
        $this->assertContains($d1, $all);
    }

    public function testGetAllBackendsDeduplicatesByObjectIdentity(): void
    {
        // Same PHP object registered under two different keys
        $shared = $this->createMock(SigningBackendInterface::class);
        $shared->method('getName')->willReturn('openssl-signing');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-a', $shared);
        $registry->registerSigningBackend('key-b', $shared);

        $this->assertCount(1, $registry->getAllBackends());
    }

    public function testGetAllBackendsKeepsSeparateInstancesWithSameName(): void
    {
        // Two distinct PHP objects that happen to share a backend name
        $instance1 = $this->createMock(SigningBackendInterface::class);
        $instance1->method('getName')->willReturn('backend-a');
        $instance2 = $this->createMock(DecryptionBackendInterface::class);
        $instance2->method('getName')->willReturn('backend-a');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-b', $instance1);
        $registry->registerDecryptionBackend('key-b', $instance2);

        $this->assertCount(2, $registry->getAllBackends());
    }

    public function testGetBackendsByNameReturnMatchingInstances(): void
    {
        $signing = $this->createMock(SigningBackendInterface::class);
        $signing->method('getName')->willReturn('backend-a');

        $decryption = $this->createMock(DecryptionBackendInterface::class);
        $decryption->method('getName')->willReturn('backend-a');

        $other = $this->createMock(SigningBackendInterface::class);
        $other->method('getName')->willReturn('openssl-signing');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-b', $signing);
        $registry->registerDecryptionBackend('key-b', $decryption);
        $registry->registerSigningBackend('other-key', $other);

        $result = $registry->getBackendsByName('backend-a');
        $this->assertCount(2, $result);
        $this->assertContains($signing, $result);
        $this->assertContains($decryption, $result);
    }

    public function testGetBackendsByNameReturnsEmptyForUnknownName(): void
    {
        $registry = $this->createRegistry();
        $this->assertSame([], $registry->getBackendsByName('no-such-backend'));
    }

    public function testGetBackendsByNameDeduplicatesByObjectIdentity(): void
    {
        // Same PHP object registered under two keys with same backend name
        $shared = $this->createMock(SigningBackendInterface::class);
        $shared->method('getName')->willReturn('openssl-signing');

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('key-a', $shared);
        $registry->registerSigningBackend('key-b', $shared);

        $this->assertCount(1, $registry->getBackendsByName('openssl-signing'));
    }

    public function testSigningFingerprintMismatchThrowsInvalidConfigurationException(): void
    {
        $backend1 = $this->createMock(SigningBackendInterface::class);
        $backend1->method('getName')->willReturn('b1');
        $backend1->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));
        $backend2 = $this->createMock(SigningBackendInterface::class);
        $backend2->method('getName')->willReturn('b2');
        $backend2->method('getPublicKeyFingerprint')->willReturn(str_repeat('b', 64));

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('my-key', $backend1);
        $registry->registerSigningBackend('my-key', $backend2);

        $this->expectException(InvalidConfigurationException::class);
        $registry->getSigningBackend('my-key');
    }

    public function testDecryptionFingerprintMismatchThrowsInvalidConfigurationException(): void
    {
        $backend1 = $this->createMock(DecryptionBackendInterface::class);
        $backend1->method('getName')->willReturn('b1');
        $backend1->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));
        $backend2 = $this->createMock(DecryptionBackendInterface::class);
        $backend2->method('getName')->willReturn('b2');
        $backend2->method('getPublicKeyFingerprint')->willReturn(str_repeat('b', 64));

        $registry = $this->createRegistry();
        $registry->registerDecryptionBackend('my-key', $backend1);
        $registry->registerDecryptionBackend('my-key', $backend2);

        $this->expectException(InvalidConfigurationException::class);
        $registry->getDecryptionBackend('my-key');
    }

    public function testSigningFingerprintCheckRunsOnlyOnce(): void
    {
        $backend1 = $this->createMock(SigningBackendInterface::class);
        $backend1->method('getName')->willReturn('b1');
        $backend1->expects($this->once())->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));
        $backend2 = $this->createMock(SigningBackendInterface::class);
        $backend2->method('getName')->willReturn('b2');
        $backend2->expects($this->once())->method('getPublicKeyFingerprint')->willReturn(str_repeat('a', 64));

        $registry = $this->createRegistry();
        $registry->registerSigningBackend('my-key', $backend1);
        $registry->registerSigningBackend('my-key', $backend2);

        $registry->getSigningBackend('my-key');
        $registry->getSigningBackend('my-key');
        $registry->getSigningBackend('my-key');
    }
}
