<?php

declare(strict_types=1);

namespace App\Backend;

use Pkcs11\Module;
use Psr\Log\LoggerInterface;

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

    public static function get(string $libraryPath, LoggerInterface $logger): Module
    {
        $logger->info("Getting PKCS#11 module for library path: $libraryPath");
        if (isset(self::$modules[$libraryPath])) {
            $logger->info("REUSE MODULE: Returning cached PKCS#11 module for library path: $libraryPath");
            return self::$modules[$libraryPath];
        }
        $logger->info("NEW MODULE: Returning new PKCS#11 module for library path: $libraryPath");
        return self::$modules[$libraryPath] = new Module($libraryPath);
    }
}
