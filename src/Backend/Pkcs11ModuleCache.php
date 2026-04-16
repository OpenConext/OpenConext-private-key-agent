<?php

declare(strict_types=1);

namespace App\Backend;

use Pkcs11\Module;

/**
 * Process-wide cache of \Pkcs11\Module instances, keyed by library path.
 *
 * Creating multiple Module instances for the same library path triggers
 * C_Initialize more than once, which yields CKR_CRYPTOKI_ALREADY_INITIALIZED.
 * This cache ensures each library is initialised exactly once per process.
 */
final class Pkcs11ModuleCache
{
    /** @var array<string, Module> */
    private static array $modules = [];

    public static function get(string $libraryPath): Module
    {
        if (! isset(self::$modules[$libraryPath])) {
            self::$modules[$libraryPath] = new Module($libraryPath);
        }

        return self::$modules[$libraryPath];
    }

    public static function has(string $libraryPath): bool
    {
        return isset(self::$modules[$libraryPath]);
    }

    /**
     * Remove all cached modules. Intended for use in tests only.
     */
    public static function reset(): void
    {
        self::$modules = [];
    }
}
