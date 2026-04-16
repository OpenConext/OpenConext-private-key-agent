<?php

declare(strict_types=1);

namespace App\Tests\Integration\Backend;

use App\Backend\Pkcs11DecryptionBackend;
use App\Backend\Pkcs11SessionCache;
use App\Config\BackendGroupConfig;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

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

    protected function tearDown(): void
    {
        Pkcs11SessionCache::reset();
    }

    public function testGetName(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11DecryptionBackend(self::$config, new NullLogger());
        $this->assertSame('hsm-test', $backend->getName());
    }

    public function testIsHealthy(): void
    {
        $this->assertNotNull(self::$config);
        $backend = new Pkcs11DecryptionBackend(self::$config, new NullLogger());
        $this->assertTrue($backend->isHealthy());
    }

    public function testGetPublicKeyFingerprint(): void
    {
        $this->assertNotNull(self::$config);
        $backend     = new Pkcs11DecryptionBackend(self::$config, new NullLogger());
        $fingerprint = $backend->getPublicKeyFingerprint();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fingerprint);
    }

    public function testSessionIsReusedAcrossMultipleCalls(): void
    {
        $this->assertNotNull(self::$config);
        $lib  = self::$config->pkcs11Lib;
        $slot = self::$config->pkcs11Slot;
        $this->assertNotNull($lib);
        $this->assertNotNull($slot);
        $name = self::$config->name;

        $backend = new Pkcs11DecryptionBackend(self::$config, new NullLogger());
        $backend->isHealthy();

        // The session must now be in the static cache.
        $this->assertTrue(Pkcs11SessionCache::has($name, $lib, $slot));
        $sessionAfterFirst = Pkcs11SessionCache::get($name, $lib, $slot);

        // A second backend instance simulates a new request (fresh DI container).
        $backend2 = new Pkcs11DecryptionBackend(self::$config, new NullLogger());
        $backend2->isHealthy();

        $sessionAfterSecond = Pkcs11SessionCache::get($name, $lib, $slot);

        $this->assertSame(
            $sessionAfterFirst,
            $sessionAfterSecond,
            'A new backend instance must reuse the cached PKCS#11 session, not open a new one',
        );
    }
}
