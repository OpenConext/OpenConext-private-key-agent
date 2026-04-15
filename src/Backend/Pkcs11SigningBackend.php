<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Crypto\DigestInfoBuilder;
use App\Exception\BackendException;
use Pkcs11\Exception;
use Pkcs11\Key;
use Pkcs11\Mechanism;
use Pkcs11\Session;
use Psr\Log\LoggerInterface;
use Throwable;

use function count;
use function extension_loaded;
use function hash;
use function hex2bin;
use function in_array;
use function putenv;
use function sprintf;

use const Pkcs11\CKA_CLASS;
use const Pkcs11\CKA_ID;
use const Pkcs11\CKA_KEY_TYPE;
use const Pkcs11\CKA_LABEL;
use const Pkcs11\CKA_MODULUS;
use const Pkcs11\CKF_SERIAL_SESSION;
use const Pkcs11\CKK_RSA;
use const Pkcs11\CKM_RSA_PKCS;
use const Pkcs11\CKO_PRIVATE_KEY;
use const Pkcs11\CKO_PUBLIC_KEY;
use const Pkcs11\CKU_USER;

final class Pkcs11SigningBackend implements SigningBackendInterface
{
    /** @var Session|null Lazy-initialized session */
    private Session|null $session = null;

    /** @var Key|null Lazy-initialized private key handle */
    private Key|null $privateKey = null;

    private string|null $publicKeyFingerprint = null;

    public function __construct(
        private readonly BackendGroupConfig $config,
        private readonly LoggerInterface $logger,
    )
    {
        if (! extension_loaded('pkcs11')) {
            throw new BackendException('pkcs11 PHP extension is not loaded');
        }
    }

    public function getName(): string
    {
        return $this->config->name;
    }

    public function isHealthy(): bool
    {
        try {
            $this->ensureSession()->getInfo();

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    public function getPublicKeyFingerprint(): string
    {
        if ($this->publicKeyFingerprint === null) {
            $this->publicKeyFingerprint = $this->computeFingerprint($this->ensureSession());
        }

        return $this->publicKeyFingerprint;
    }

    public function sign(string $hash, string $algorithm): string
    {
        $privateKey = $this->ensurePrivateKey();

        $digestInfo = DigestInfoBuilder::prepend($hash, $algorithm);

        try {
            $mechanism = new Mechanism(CKM_RSA_PKCS);

            $res=$privateKey->sign($mechanism, $digestInfo);
            $this->logger->info('SIGN: Signed hash {hash} with algorithm {algorithm} using private key {handle} in session {session}',
                ['hash' => base64_encode($hash), 'algorithm' => $algorithm, 'handle' => $privateKey, 'session' => $this->session]);
            return $res;
        } catch (Exception $e) {
            if ($this->isSessionError($e)) {
                $this->logger->info('Session error {error} for private key {handle}, re-finding', ['error' => $e->getMessage(), 'handle' => $privateKey]);;

                $this->session    = null;
                $this->privateKey = null;
                $privateKey       = $this->ensurePrivateKey();
                $mechanism        = new Mechanism(CKM_RSA_PKCS);

                $res = $privateKey->sign($mechanism, $digestInfo);

                $this->logger->info('SIGN: Signed hash {hash} with algorithm {algorithm} using private key {handle} in session {session}',
                    ['hash' => base64_encode($hash), 'algorithm' => $algorithm, 'handle' => $privateKey, 'session' => $this->session]);

                return $res;
            }

            throw new BackendException(sprintf(
                'PKCS#11 signing failed for backend "%s": %s',
                $this->config->name,
                $e->getMessage(),
            ), $e);
        }
    }

    private function ensurePrivateKey(): Key
    {
        $this->logger->info('Ensuring private key for backend "{backend}"', ['backend' => $this->config->name]);
        $session = $this->ensureSession();
        if ($this->privateKey === null) {
            $this->logger->info('Private key not found for backend "{backend}", re-finding', ['backend' => $this->config->name]);
            $this->privateKey = $this->findPrivateKey($session);
            $this->logger->info('NEW OBJECT: Found private signing key {handle} for use in session {session}"', ['handle' => $this->privateKey, 'session' => $session]);
        } else {
            $this->logger->info('REUSE OBJECT: Reusing private signing key {handle} in session {session}', ['handle' => $this->privateKey, 'session' => $session]);
        }

        return $this->privateKey;
    }

    private function ensureSession(): Session
    {
        $this->logger->info('Ensuring PKCS#11 session for backend "{backend}"', ['backend' => $this->config->name]);
        if ($this->session !== null) {
            $this->logger->info('REUSE SESSION: Reusing existing PKCS#11 session {session} for backend "{backend}"', ['backend' => $this->config->name, 'session'=>$this->session]);
            return $this->session;
        }

        if ($this->config->pkcs11Lib === null) {
            throw new BackendException(sprintf('pkcs11_lib not configured for backend "%s"', $this->config->name));
        }

        foreach ($this->config->environment as $key => $value) {
            putenv($key . '=' . $value);
        }

        try {
            $module = Pkcs11ModuleCache::get($this->config->pkcs11Lib, $this->logger);

            $this->logger->info('Creating new PKCS#11 session for backend "{backend}"', ['backend' => $this->config->name]);

            $this->logger->info('Calling getSlotList');
            $slotList = $module->getSlotList();
            $slotId   = $slotList[$this->config->pkcs11Slot]
                ?? throw new BackendException(sprintf('Slot %d not found', $this->config->pkcs11Slot));

            $this->logger->info('Creating new PKCS#11 session for backend "{backend}", slot: {slot}', ['backend' => $this->config->name, 'slot' => $slotId]);

            $session = $module->openSession($slotId, CKF_SERIAL_SESSION);
            $this->logger->info('NEW SESSION: Got new session {session}', ['session' => $session]);;
            if ($this->config->pkcs11Pin !== null) {
                try {
                    $this->logger->info('Logging in to PKCS#11 session {session}', ['session' => $session]);
                    $session->login(CKU_USER, $this->config->pkcs11Pin);
                } catch (Exception $e) {
                    // CKR_USER_ALREADY_LOGGED_IN: another session on this token is already authenticated;
                    // the spec treats the whole token as logged-in, so this session is usable as-is.
                    if ($e->getCode() !== 0x100) {
                        throw $e;
                    }
                    $this->logger->info('Session {session} already logged in, continuing', ['session' => $session]);
                }
            }

            $this->session    = $session;

            $bNeededNewKey = (null === $this->privateKey);
            $this->privateKey = $this->findPrivateKey($session);
            if ($bNeededNewKey) {
                $this->logger->info('NEW OBJECT: Found private signing key {handle} for use in session {session}"', ['handle' => $this->privateKey, 'session' => $session]);
            } else {
                $this->logger->info('REUSE OBJECT: Reusing private signing key {handle} in session {session}', ['handle' => $this->privateKey, 'session' => $session]);
            }

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

    private function findPrivateKey(Session $session): Key
    {
        $this->logger->info('Finding private key for PKCS#11 session"', ['session' => $session]);
        $template = [
            CKA_CLASS => CKO_PRIVATE_KEY,
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

        return $objects[0];
    }

    private function computeFingerprint(Session $session): string
    {
        $template = [
            CKA_CLASS => CKO_PUBLIC_KEY,
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
            throw new BackendException(sprintf('No public key found for fingerprint in backend "%s"', $this->config->name));
        }

        $attrs = $objects[0]->getAttributeValue([CKA_MODULUS]);

        return hash('sha256', $attrs[CKA_MODULUS]);
    }

    private function isSessionError(Exception $e): bool
    {
        $code = $e->getCode();

        // CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_DEVICE_ERROR
        return in_array($code, [0x000000B0, 0x000000B3, 0x00000030], true);
    }
}
