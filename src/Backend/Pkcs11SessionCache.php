<?php

declare(strict_types=1);

namespace App\Backend;

use Pkcs11\Session;

use function sprintf;

/**
 * Per-worker cache of \Pkcs11\Session instances.
 *
 * In FrankenPHP worker mode, each PHP worker runs as a long-lived thread. Static
 * class properties persist for the worker's lifetime (up to the configured
 * max_requests recycle limit), so sessions opened in earlier requests are reused
 * automatically — avoiding repeated C_OpenSession / C_Login round-trips to the HSM.
 *
 * Sessions are keyed by backend name + library path + slot index so that distinct
 * backend configurations never share a session handle.
 */
final class Pkcs11SessionCache
{
    /** @var array<string, Session> */
    private static array $sessions = [];

    public static function cacheKey(string $backendName, string $libraryPath, int $slotIndex): string
    {
        return sprintf('%s:%s:%d', $backendName, $libraryPath, $slotIndex);
    }

    public static function get(string $backendName, string $libraryPath, int $slotIndex): Session|null
    {
        return self::$sessions[self::cacheKey($backendName, $libraryPath, $slotIndex)] ?? null;
    }

    public static function set(string $backendName, string $libraryPath, int $slotIndex, Session $session): void
    {
        self::$sessions[self::cacheKey($backendName, $libraryPath, $slotIndex)] = $session;
    }

    public static function has(string $backendName, string $libraryPath, int $slotIndex): bool
    {
        return isset(self::$sessions[self::cacheKey($backendName, $libraryPath, $slotIndex)]);
    }

    public static function invalidate(string $backendName, string $libraryPath, int $slotIndex): void
    {
        unset(self::$sessions[self::cacheKey($backendName, $libraryPath, $slotIndex)]);
    }

    /**
     * Remove all cached sessions. Intended for use in tests only.
     */
    public static function reset(): void
    {
        self::$sessions = [];
    }
}
