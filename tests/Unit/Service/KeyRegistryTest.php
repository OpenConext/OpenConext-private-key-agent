<?php

declare(strict_types=1);

namespace App\Tests\Unit\Service;

use App\Backend\OpenSslBackend;
use App\Exception\KeyNotFoundException;
use App\Service\KeyRegistry;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function openssl_pkey_export_to_file;
use function openssl_pkey_new;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_RSA;

class KeyRegistryTest extends TestCase
{
    private static string $keyPath;

    public static function setUpBeforeClass(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair, 'Failed to generate RSA key pair');
        self::$keyPath = tempnam(sys_get_temp_dir(), 'rsa_') . '.pem';
        openssl_pkey_export_to_file($keyPair, self::$keyPath);
    }

    public static function tearDownAfterClass(): void
    {
        if (! file_exists(self::$keyPath)) {
            return;
        }

        unlink(self::$keyPath);
    }

    private function createBackend(string $name): OpenSslBackend
    {
        return new OpenSslBackend($name, self::$keyPath);
    }

    public function testGetSigningBackendReturnsRegisteredBackend(): void
    {
        $backend  = $this->createBackend('my-key');
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
        $backend  = $this->createBackend('my-key');
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['decrypt']);

        $this->expectException(KeyNotFoundException::class);
        $registry->getSigningBackend('my-key');
    }

    public function testGetDecryptionBackendReturnsRegisteredBackend(): void
    {
        $backend  = $this->createBackend('my-key');
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
        $backend  = $this->createBackend('my-key');
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign']);

        $this->expectException(KeyNotFoundException::class);
        $registry->getDecryptionBackend('my-key');
    }

    public function testKeyWithBothOperationsSupportsSigningAndDecryption(): void
    {
        $backend  = $this->createBackend('my-key');
        $registry = new KeyRegistry();
        $registry->register('my-key', $backend, ['sign', 'decrypt']);

        $this->assertSame($backend, $registry->getSigningBackend('my-key'));
        $this->assertSame($backend, $registry->getDecryptionBackend('my-key'));
    }

    public function testGetAllBackendsReturnsAllRegisteredBackends(): void
    {
        $b1 = $this->createBackend('key-a');
        $b2 = $this->createBackend('key-b');

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
        $backend  = $this->createBackend('my-key');
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
