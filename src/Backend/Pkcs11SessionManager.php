<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use Pkcs11\Exception;
use Pkcs11\Key;
use Pkcs11\Session;
use Psr\Log\LoggerInterface;
use Throwable;

use function count;
use function hex2bin;
use function in_array;
use function putenv;
use function sprintf;

use const Pkcs11\CKA_CLASS;
use const Pkcs11\CKA_ID;
use const Pkcs11\CKA_KEY_TYPE;
use const Pkcs11\CKA_LABEL;
use const Pkcs11\CKF_SERIAL_SESSION;
use const Pkcs11\CKK_RSA;
use const Pkcs11\CKO_PRIVATE_KEY;
use const Pkcs11\CKU_USER;

/**
 * Manages PKCS#11 session lifecycle and private key access across FrankenPHP worker requests.
 *
 * Sessions are cached in a static map (Pkcs11SessionCache) so that each long-lived worker
 * thread reuses the same HSM session across requests, avoiding repeated C_OpenSession /
 * C_Login round-trips. The private key handle is re-fetched on each new backend instance
 * (per request) but reuses the cached session so the HSM lookup is cheap.
 */
final class Pkcs11SessionManager
{
    /** @var Key|null Lazy-initialized private key handle, valid for the current session */
    private Key|null $privateKey = null;

    public function __construct(
        private readonly BackendGroupConfig $config,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function ensureSession(): Session
    {
        $lib  = $this->config->pkcs11Lib
            ?? throw new BackendException(sprintf('pkcs11_lib not configured for backend "%s"', $this->config->name));
        $slot = $this->config->pkcs11Slot
            ?? throw new BackendException(sprintf('pkcs11_slot not configured for backend "%s"', $this->config->name));
        $name = $this->config->name;

        $cached = Pkcs11SessionCache::get($name, $lib, $slot);
        if ($cached !== null) {
            $this->logger->debug(
                'Reusing existing PKCS#11 session',
                ['backend' => $name, 'lib' => $lib, 'slot' => $slot],
            );

            return $cached;
        }

        // putenv() modifies the process-wide C environment, shared across all FrankenPHP worker
        // threads. All workers set the same values, so concurrent calls are idempotent in practice.
        foreach ($this->config->environment as $key => $value) {
            putenv($key . '=' . $value);
        }

        try {
            $moduleIsNew = ! Pkcs11ModuleCache::has($lib);
            $module      = Pkcs11ModuleCache::get($lib);
            $this->logger->debug(
                $moduleIsNew ? 'Loaded PKCS#11 module' : 'Reusing cached PKCS#11 module',
                ['backend' => $name, 'lib' => $lib],
            );

            $slotList = $module->getSlotList();
            $slotId   = $slotList[$slot]
                ?? throw new BackendException(sprintf('Slot %d not found', $slot));

            $session = $module->openSession($slotId, CKF_SERIAL_SESSION);
            if ($this->config->pkcs11Pin !== null) {
                try {
                    $session->login(CKU_USER, $this->config->pkcs11Pin);
                } catch (Exception $e) {
                    // CKR_USER_ALREADY_LOGGED_IN: another session on this token is already authenticated;
                    // the spec treats the whole token as logged-in, so this session is usable as-is.
                    if ($e->getCode() !== 0x100) {
                        throw $e;
                    }
                }
            }

            Pkcs11SessionCache::set($name, $lib, $slot, $session);
            $this->logger->info(
                'Opened new PKCS#11 session',
                ['backend' => $name, 'lib' => $lib, 'slot' => $slot],
            );

            $this->privateKey = $this->findPrivateKey($session);

            return $session;
        } catch (BackendException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new BackendException(sprintf(
                'PKCS#11 session init failed for backend "%s": %s',
                $this->config->name,
                $e->getMessage(),
            ), $e);
        }
    }

    public function ensurePrivateKey(): Key
    {
        $session = $this->ensureSession();
        if ($this->privateKey === null) {
            $this->privateKey = $this->findPrivateKey($session);
        }

        return $this->privateKey;
    }

    public function invalidateSession(): void
    {
        $lib  = $this->config->pkcs11Lib;
        $slot = $this->config->pkcs11Slot;
        if ($lib !== null && $slot !== null) {
            Pkcs11SessionCache::invalidate($this->config->name, $lib, $slot);
        }

        $this->privateKey = null;
    }

    public function isSessionError(Exception $e): bool
    {
        $code = $e->getCode();

        // CKR_SESSION_CLOSED (0xB0), CKR_SESSION_HANDLE_INVALID (0xB3), CKR_DEVICE_ERROR (0x30),
        // CKR_DEVICE_REMOVED (0x32), CKR_TOKEN_NOT_PRESENT (0xE0), CKR_TOKEN_NOT_RECOGNIZED (0xE1)
        return in_array($code, [0x000000B0, 0x000000B3, 0x00000030, 0x00000032, 0x000000E0, 0x000000E1], true);
    }

    private function findPrivateKey(Session $session): Key
    {
        $template = [
            CKA_CLASS    => CKO_PRIVATE_KEY,
            CKA_KEY_TYPE => CKK_RSA,
        ];

        if ($this->config->pkcs11KeyLabel !== null) {
            $template[CKA_LABEL] = $this->config->pkcs11KeyLabel;
        }

        if ($this->config->pkcs11KeyId !== null) {
            $template[CKA_ID] = hex2bin($this->config->pkcs11KeyId);
        }

        $objects = $session->findObjects($template);
        if (count($objects) === 0) {
            throw new BackendException(sprintf(
                'No private key found in PKCS#11 backend "%s" with label "%s"',
                $this->config->name,
                $this->config->pkcs11KeyLabel ?? $this->config->pkcs11KeyId,
            ));
        }

        if (count($objects) > 1) {
            $this->logger->warning(
                'Multiple private keys match the key template; using the first one',
                [
                    'backend' => $this->config->name,
                    'count'   => count($objects),
                    'label'   => $this->config->pkcs11KeyLabel,
                    'keyId'   => $this->config->pkcs11KeyId,
                ],
            );
        }

        return $objects[0];
    }
}
