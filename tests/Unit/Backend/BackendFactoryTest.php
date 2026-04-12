<?php

declare(strict_types=1);

namespace App\Tests\Unit\Backend;

use App\Backend\BackendFactory;
use App\Backend\OpenSslBackendTypeFactory;
use App\Backend\OpenSslDecryptionBackend;
use App\Backend\OpenSslSigningBackend;
use App\Backend\Pkcs11BackendTypeFactory;
use App\Backend\Pkcs11SigningBackend;
use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function openssl_pkey_export_to_file;
use function openssl_pkey_new;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_RSA;

class BackendFactoryTest extends TestCase
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

    public function testCreateSigningBackendForOpenssl(): void
    {
        $config  = new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: self::$keyPath);
        $factory = new BackendFactory([new OpenSslBackendTypeFactory(), new Pkcs11BackendTypeFactory()]);

        $backend = $factory->createSigningBackend($config);
        $this->assertInstanceOf(OpenSslSigningBackend::class, $backend);
    }

    public function testCreateDecryptionBackendForOpenssl(): void
    {
        $config  = new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: self::$keyPath);
        $factory = new BackendFactory([new OpenSslBackendTypeFactory(), new Pkcs11BackendTypeFactory()]);

        $backend = $factory->createDecryptionBackend($config);
        $this->assertInstanceOf(OpenSslDecryptionBackend::class, $backend);
    }

    #[RequiresPhpExtension('pkcs11')]
    public function testCreateSigningBackendForPkcs11(): void
    {
        $config  = new BackendGroupConfig(
            name: 'hsm',
            type: 'pkcs11',
            pkcs11Lib: '/usr/lib/softhsm/libsofthsm2.so',
            pkcs11Slot: 0,
            pkcs11Pin: '1234',
            pkcs11KeyLabel: 'test',
        );
        $factory = new BackendFactory([new OpenSslBackendTypeFactory(), new Pkcs11BackendTypeFactory()]);

        $backend = $factory->createSigningBackend($config);
        $this->assertInstanceOf(Pkcs11SigningBackend::class, $backend);
    }

    public function testUnknownBackendTypeThrows(): void
    {
        $config  = new BackendGroupConfig(name: 'test', type: 'unknown', keyPath: '/dev/null');
        $factory = new BackendFactory([new OpenSslBackendTypeFactory()]);

        $this->expectException(BackendException::class);
        $this->expectExceptionMessage('Unknown backend type "unknown"');
        $factory->createSigningBackend($config);
    }
}
