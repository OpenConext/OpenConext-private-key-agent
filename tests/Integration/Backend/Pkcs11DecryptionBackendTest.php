<?php

declare(strict_types=1);

namespace App\Tests\Integration\Backend;

use App\Backend\Pkcs11DecryptionBackend;
use App\Config\BackendGroupConfig;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function getenv;

#[RequiresPhpExtension('pkcs11')]
class Pkcs11DecryptionBackendTest extends TestCase
{
    private static BackendGroupConfig|null $config = null;

    public static function setUpBeforeClass(): void
    {
        $lib   = getenv('PKCS11_LIB') ?: '/usr/lib/softhsm/libsofthsm2.so';
        $pin   = getenv('PKCS11_PIN') ?: '1234';
        $label = getenv('PKCS11_KEY_LABEL') ?: 'test-signing-key';
        $slot  = (int) (getenv('PKCS11_SLOT') ?: '0');

        if (! file_exists($lib)) {
            self::markTestSkipped('PKCS#11 library not found: ' . $lib);
        }

        self::$config = new BackendGroupConfig(
            name: 'hsm-test',
            type: 'pkcs11',
            pkcs11Lib: $lib,
            pkcs11Slot: $slot,
            pkcs11Pin: $pin,
            pkcs11KeyLabel: $label,
        );
    }

    public function testGetName(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11DecryptionBackend(self::$config);
        $this->assertSame('hsm-test', $backend->getName());
    }

    public function testIsHealthy(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11DecryptionBackend(self::$config);
        $this->assertTrue($backend->isHealthy());
    }

    public function testGetPublicKeyFingerprint(): void
    {
        $this->assertNotNull(self::$config);
        $backend     = new Pkcs11DecryptionBackend(self::$config);
        $fingerprint = $backend->getPublicKeyFingerprint();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fingerprint);
    }
}
