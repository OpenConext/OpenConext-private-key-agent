<?php

declare(strict_types=1);

/**
 * FrankenPHP worker entry-point.
 *
 * Initialises every PKCS#11 backend OUTSIDE the frankenphp_handle_request() loop
 * so that HSM sessions are established at worker startup rather than on the first
 * in-flight request. The open session handles are kept alive in Pkcs11SessionCache
 * (static property per worker thread) and reused for all subsequent requests.
 *
 * Mirrors the behaviour of runtime/frankenphp-symfony Runner:
 *   - sets APP_RUNTIME_MODE before kernel boot
 *   - restores non-HTTP $_SERVER keys on every request to prevent state drift
 *   - calls $kernel->terminate() outside the frankenphp_handle_request() callback
 *   - gc_collect_cycles() after each request
 *   - supports FRANKENPHP_LOOP_MAX for worker recycling
 */

use App\Kernel;
use App\Service\KeyRegistryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\HttpFoundation\Request;

require_once dirname(__DIR__) . '/vendor/autoload.php';

if (is_file($envFile = dirname(__DIR__) . '/.env')) {
    (new Dotenv())->bootEnv($envFile);
}

// Required so Symfony knows this is a FrankenPHP worker (same value set by the
// runtime/frankenphp-symfony Runner before entering the loop).
$_SERVER['APP_RUNTIME_MODE'] = 'web=1&worker=1';

// Capture the initial non-HTTP server state. FrankenPHP populates HTTP_* vars
// fresh for each request; restoring the base state on every iteration prevents
// request-to-request $_SERVER drift.
$server = array_filter(
    $_SERVER,
    static fn (string $key) => !str_starts_with($key, 'HTTP_'),
    ARRAY_FILTER_USE_KEY,
);
$server['APP_RUNTIME_MODE'] = 'web=1&worker=1';

// ── Bootstrap Symfony kernel once per worker ─────────────────────────────────
$kernel = new Kernel($_SERVER['APP_ENV'] ?? 'prod', (bool) ($_SERVER['APP_DEBUG'] ?? false));
$kernel->boot();

// ── Pre-initialise backends ───────────────────────────────────────────────────
// For PKCS#11 backends this opens the HSM session and performs C_Login, caching
// the session handle in Pkcs11SessionCache. Every subsequent request in this
// worker will find the open session in the cache and skip C_OpenSession / C_Login.
/** @var KeyRegistryInterface $registry */
$registry = $kernel->getContainer()->get(KeyRegistryInterface::class);

/** @var LoggerInterface $workerLogger */
$workerLogger = $kernel->getContainer()->get(LoggerInterface::class);

foreach ($registry->getAllBackends() as $backend) {
    if (! $backend->isHealthy()) {
        error_log(sprintf(
            '[worker] Backend "%s" reported unhealthy at startup — will retry on first request',
            $backend->getName(),
        ));
    }
}

// ── Request loop ─────────────────────────────────────────────────────────────
$maxRequests = max(0, (int) ($_SERVER['FRANKENPHP_LOOP_MAX'] ?? $_ENV['FRANKENPHP_LOOP_MAX'] ?? 2000));
$loops       = 0;
$sfRequest   = null;
$sfResponse  = null;

$workerId    = getmypid();
// Log every MEM_LOG_INTERVAL requests; use ~1 % of maxRequests (floored to 100).
$memLogInterval = $maxRequests > 0 ? max(100, (int) ($maxRequests / 100)) : 500;

$workerLogger->debug('Worker started', [
    'pid'           => $workerId,
    'maxRequests'   => $maxRequests,
    'memLogInterval'=> $memLogInterval,
    'initialMemory' => (int) (memory_get_usage(true) / 1024) . ' KB',
]);

ignore_user_abort(true);

do {
    $ret = frankenphp_handle_request(static function () use ($kernel, $server, &$sfRequest, &$sfResponse): void {
        // Restore non-HTTP server state for this request.
        $_SERVER += $server;

        $sfRequest  = Request::createFromGlobals();
        $sfResponse = $kernel->handle($sfRequest);
        $sfResponse->send();
    });

    // terminate() must run after the response has been sent (outside the callback).
    if ($sfRequest !== null && $sfResponse !== null) {
        $kernel->terminate($sfRequest, $sfResponse);
        $sfRequest  = null;
        $sfResponse = null;
    }

    gc_collect_cycles();

    ++$loops;

    // Periodic debug snapshot: loop count, live memory, peak memory.
    if ($memLogInterval > 0 && ($loops % $memLogInterval) === 0) {
        $workerLogger->debug('Worker loop snapshot', [
            'pid'      => $workerId,
            'loop'     => $loops,
            'maxLoops' => $maxRequests > 0 ? $maxRequests : 'unlimited',
            'memory'   => (int) (memory_get_usage(true) / 1024) . ' KB',
            'peak'     => (int) (memory_get_peak_usage(true) / 1024) . ' KB',
        ]);
    }
} while ($ret && ($maxRequests === 0 || $loops < $maxRequests));

$workerLogger->debug('Worker recycling', [
    'pid'    => $workerId,
    'loops'  => $loops,
    'memory' => (int) (memory_get_usage(true) / 1024) . ' KB',
    'peak'   => (int) (memory_get_peak_usage(true) / 1024) . ' KB',
]);
