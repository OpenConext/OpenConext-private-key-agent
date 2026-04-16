<?php

declare(strict_types=1);

namespace App\Tests\Unit\Backend;

use App\Backend\Pkcs11SessionCache;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for Pkcs11SessionCache that do not require the pkcs11 extension.
 *
 * Tests that exercise set()/get() with real \Pkcs11\Session objects (which
 * cannot be mocked — the extension class is not reflectable) are covered by
 * the integration tests in Pkcs11SigningBackendTest and
 * Pkcs11DecryptionBackendTest.
 */
class Pkcs11SessionCacheTest extends TestCase
{
    private const string LIB  = '/usr/lib/softhsm/libsofthsm2.so';
    private const int SLOT    = 0;
    private const string NAME = 'test-backend';

    protected function tearDown(): void
    {
        Pkcs11SessionCache::reset();
    }

    public function testHasReturnsFalseWhenNotCached(): void
    {
        $this->assertFalse(Pkcs11SessionCache::has(self::NAME, self::LIB, self::SLOT));
    }

    public function testGetReturnsNullWhenNotCached(): void
    {
        $this->assertNull(Pkcs11SessionCache::get(self::NAME, self::LIB, self::SLOT));
    }

    public function testResetIsIdempotentOnEmptyCache(): void
    {
        Pkcs11SessionCache::reset();
        $this->assertFalse(Pkcs11SessionCache::has(self::NAME, self::LIB, self::SLOT));
    }

    public function testInvalidateOnNonExistentEntryDoesNotThrow(): void
    {
        Pkcs11SessionCache::invalidate(self::NAME, self::LIB, self::SLOT);
        $this->assertFalse(Pkcs11SessionCache::has(self::NAME, self::LIB, self::SLOT));
    }

    public function testCacheKeyFormat(): void
    {
        $this->assertSame('mybackend:/lib/foo.so:3', Pkcs11SessionCache::cacheKey('mybackend', '/lib/foo.so', 3));
    }

    public function testCacheKeyIsDifferentForDifferentBackends(): void
    {
        $this->assertNotSame(
            Pkcs11SessionCache::cacheKey('backend-a', self::LIB, self::SLOT),
            Pkcs11SessionCache::cacheKey('backend-b', self::LIB, self::SLOT),
        );
    }

    public function testCacheKeyIsDifferentForDifferentSlots(): void
    {
        $this->assertNotSame(
            Pkcs11SessionCache::cacheKey(self::NAME, self::LIB, 0),
            Pkcs11SessionCache::cacheKey(self::NAME, self::LIB, 1),
        );
    }
}
