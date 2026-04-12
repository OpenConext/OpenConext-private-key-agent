<?php

declare(strict_types=1);

namespace App\Tests\Integration\Backend;

use App\Backend\Pkcs11SigningBackend;
use App\Config\BackendGroupConfig;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

use function extension_loaded;
use function file_exists;
use function getenv;
use function hash;

#[RequiresPhpExtension('pkcs11')]
class Pkcs11SigningBackendTest extends TestCase
{
    private static BackendGroupConfig|null $config = null;

    public static function setUpBeforeClass(): void
    {
        if (! extension_loaded('pkcs11')) {
            self::markTestSkipped('pkcs11 extension not loaded');
        }

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

    public function testSignSha256(): void
    {
        $this->assertNotNull(self::$config);
        $backend   = new Pkcs11SigningBackend(self::$config);
        $hash      = hash('sha256', 'test data', true);
        $signature = $backend->sign($hash, 'rsa-pkcs1-v1_5-sha256');

        $this->assertNotEmpty($signature);
        $this->assertNotEmpty($backend->getPublicKeyFingerprint());
    }

    public function testIsHealthy(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11SigningBackend(self::$config);
        $this->assertTrue($backend->isHealthy());
    }

    public function testGetName(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11SigningBackend(self::$config);
        $this->assertSame('hsm-test', $backend->getName());
    }
}
