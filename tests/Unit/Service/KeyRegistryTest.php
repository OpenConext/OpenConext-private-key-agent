<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Service;

use OpenConext\PrivateKeyAgent\Backend\DecryptionBackendInterface;
use OpenConext\PrivateKeyAgent\Backend\SigningBackendInterface;
use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\KeyNotFoundException;
use OpenConext\PrivateKeyAgent\Service\KeyRegistry;
use PHPUnit\Framework\TestCase;

class KeyRegistryTest extends TestCase
{
    private function createBackend(): SigningBackendInterface&DecryptionBackendInterface
    {
        return new class implements SigningBackendInterface, DecryptionBackendInterface {
            public function getName(): string
            {
                return 'test-key';
            }

            public function isHealthy(): bool
            {
                return true;
            }

            public function sign(string $hash, SigningAlgorithm $algorithm): string
            {
                return '';
            }

            public function decrypt(string $ciphertext, EncryptionAlgorithm $algorithm): string
            {
                return '';
            }
        };
    }

    public function testGetSigningBackendReturnsRegisteredBackend(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign']);

        $result = $registry->getSigningBackend('my-key');
        $this->assertSame($backend, $result);
    }

    public function testGetSigningBackendThrowsWhenKeyNotFound(): void
    {
        $registry = new KeyRegistry();

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessage('no-such-key');
        $registry->getSigningBackend('no-such-key');
    }

    public function testGetSigningBackendThrowsWhenOperationNotPermitted(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['decrypt']);

        $this->expectException(KeyNotFoundException::class);
        $registry->getSigningBackend('my-key');
    }

    public function testGetDecryptionBackendReturnsRegisteredBackend(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['decrypt']);

        $result = $registry->getDecryptionBackend('my-key');
        $this->assertSame($backend, $result);
    }

    public function testGetDecryptionBackendThrowsWhenKeyNotFound(): void
    {
        $registry = new KeyRegistry();

        $this->expectException(KeyNotFoundException::class);
        $registry->getDecryptionBackend('no-such-key');
    }

    public function testGetDecryptionBackendThrowsWhenOperationNotPermitted(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign']);

        $this->expectException(KeyNotFoundException::class);
        $registry->getDecryptionBackend('my-key');
    }

    public function testKeyWithBothOperationsSupportsSigningAndDecryption(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign', 'decrypt']);

        $this->assertSame($backend, $registry->getSigningBackend('my-key'));
        $this->assertSame($backend, $registry->getDecryptionBackend('my-key'));
    }

    public function testGetAllBackendsReturnsAllRegisteredBackends(): void
    {
        $b1 = $this->createBackend();
        $b2 = $this->createBackend();

        $registry = new KeyRegistry();
        $registry->register('key-a', $b1, ['sign']);
        $registry->register('key-b', $b2, ['decrypt']);

        $all = $registry->getAllBackends();
        $this->assertCount(2, $all);
        $this->assertContains($b1, $all);
        $this->assertContains($b2, $all);
    }

    public function testGetAllBackendsReturnsEmptyWhenNoneRegistered(): void
    {
        $registry = new KeyRegistry();
        $this->assertSame([], $registry->getAllBackends());
    }

    public function testFindBackendReturnsBackendForKnownKey(): void
    {
        $backend  = $this->createBackend();
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign']);

        $this->assertSame($backend, $registry->findBackend('my-key'));
    }

    public function testFindBackendReturnsNullForUnknownKey(): void
    {
        $registry = new KeyRegistry();
        $this->assertNull($registry->findBackend('no-such-key'));
    }
}
