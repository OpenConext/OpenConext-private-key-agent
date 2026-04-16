<?php

declare(strict_types=1);

namespace App\Tests\Unit\Backend;

use App\Backend\Pkcs11ModuleCache;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function getenv;

class Pkcs11ModuleCacheTest extends TestCase
{
    protected function tearDown(): void
    {
        Pkcs11ModuleCache::reset();
    }

    public function testHasReturnsFalseForUnknownPath(): void
    {
        $this->assertFalse(Pkcs11ModuleCache::has('/nonexistent/lib.so'));
    }

    public function testResetClearsAllEntries(): void
    {
        // has() should return false for every path after reset even without
        // ever populating the cache, which also validates that reset() itself
        // is idempotent.
        Pkcs11ModuleCache::reset();
        $this->assertFalse(Pkcs11ModuleCache::has('/some/lib.so'));
    }

    #[RequiresPhpExtension('pkcs11')]
    public function testGetCachesModuleForSamePath(): void
    {
        $lib = getenv('PKCS11_LIB') ?: '/usr/lib/softhsm/libsofthsm2.so';

        if (! file_exists($lib)) {
            $this->markTestSkipped('PKCS#11 library not found: ' . $lib);
        }

        $this->assertFalse(Pkcs11ModuleCache::has($lib));

        $first = Pkcs11ModuleCache::get($lib);
        $this->assertTrue(Pkcs11ModuleCache::has($lib));

        $second = Pkcs11ModuleCache::get($lib);
        $this->assertSame($first, $second, 'get() must return the same Module instance for the same path');
    }

    #[RequiresPhpExtension('pkcs11')]
    public function testResetClearsExistingEntries(): void
    {
        $lib = getenv('PKCS11_LIB') ?: '/usr/lib/softhsm/libsofthsm2.so';

        if (! file_exists($lib)) {
            $this->markTestSkipped('PKCS#11 library not found: ' . $lib);
        }

        Pkcs11ModuleCache::get($lib);
        $this->assertTrue(Pkcs11ModuleCache::has($lib));

        Pkcs11ModuleCache::reset();
        $this->assertFalse(Pkcs11ModuleCache::has($lib));
    }
}
