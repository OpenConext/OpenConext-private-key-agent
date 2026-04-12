<?php

declare(strict_types=1);

namespace App\Tests\Unit\Backend;

use App\Backend\OpenSslBackendTypeFactory;
use App\Backend\OpenSslDecryptionBackend;
use App\Backend\OpenSslSigningBackend;
use App\Config\BackendGroupConfig;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function openssl_pkey_export_to_file;
use function openssl_pkey_new;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_RSA;

class OpenSslBackendTypeFactoryTest extends TestCase
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

    public function testSupportsOpenSslType(): void
    {
        $factory = new OpenSslBackendTypeFactory();
        $this->assertTrue($factory->supports('openssl'));
    }

    public function testDoesNotSupportOtherTypes(): void
    {
        $factory = new OpenSslBackendTypeFactory();
        $this->assertFalse($factory->supports('pkcs11'));
        $this->assertFalse($factory->supports('unknown'));
    }

    public function testCreateSigningBackend(): void
    {
        $config  = new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: self::$keyPath);
        $factory = new OpenSslBackendTypeFactory();

        $backend = $factory->createSigningBackend($config);
        $this->assertInstanceOf(OpenSslSigningBackend::class, $backend);
    }

    public function testCreateDecryptionBackend(): void
    {
        $config  = new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: self::$keyPath);
        $factory = new OpenSslBackendTypeFactory();

        $backend = $factory->createDecryptionBackend($config);
        $this->assertInstanceOf(OpenSslDecryptionBackend::class, $backend);
    }
}
