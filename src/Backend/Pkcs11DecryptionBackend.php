<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use Pkcs11\Exception;
use Pkcs11\Key;
use Pkcs11\Mechanism;
use Pkcs11\RsaOaepParams;
use Pkcs11\Session;
use Throwable;

use function assert;
use function count;
use function extension_loaded;
use function hash;
use function hex2bin;
use function in_array;
use function putenv;
use function sprintf;
use function strlen;

use const Pkcs11\CKA_CLASS;
use const Pkcs11\CKA_ID;
use const Pkcs11\CKA_KEY_TYPE;
use const Pkcs11\CKA_LABEL;
use const Pkcs11\CKA_MODULUS;
use const Pkcs11\CKF_SERIAL_SESSION;
use const Pkcs11\CKG_MGF1_SHA1;
use const Pkcs11\CKG_MGF1_SHA224;
use const Pkcs11\CKG_MGF1_SHA256;
use const Pkcs11\CKG_MGF1_SHA384;
use const Pkcs11\CKG_MGF1_SHA512;
use const Pkcs11\CKK_RSA;
use const Pkcs11\CKM_RSA_PKCS;
use const Pkcs11\CKM_RSA_PKCS_OAEP;
use const Pkcs11\CKM_SHA224;
use const Pkcs11\CKM_SHA256;
use const Pkcs11\CKM_SHA384;
use const Pkcs11\CKM_SHA512;
use const Pkcs11\CKM_SHA_1;
use const Pkcs11\CKO_PRIVATE_KEY;
use const Pkcs11\CKO_PUBLIC_KEY;
use const Pkcs11\CKU_USER;

final class Pkcs11DecryptionBackend implements DecryptionBackendInterface
{
    private Session|null $session             = null;
    private Key|null $privateKey              = null;
    private string|null $publicKeyFingerprint = null;
    private int|null $modulusBytes            = null;

    private const array MECHANISM_MAP = [
        'rsa-pkcs1-v1_5'             => CKM_RSA_PKCS,
        'rsa-pkcs1-oaep-mgf1-sha1'   => CKM_RSA_PKCS_OAEP,
        'rsa-pkcs1-oaep-mgf1-sha224' => CKM_RSA_PKCS_OAEP,
        'rsa-pkcs1-oaep-mgf1-sha256' => CKM_RSA_PKCS_OAEP,
        'rsa-pkcs1-oaep-mgf1-sha384' => CKM_RSA_PKCS_OAEP,
        'rsa-pkcs1-oaep-mgf1-sha512' => CKM_RSA_PKCS_OAEP,
    ];

    private const array OAEP_HASH_MAP = [
        'rsa-pkcs1-oaep-mgf1-sha1'   => CKM_SHA_1,
        'rsa-pkcs1-oaep-mgf1-sha224' => CKM_SHA224,
        'rsa-pkcs1-oaep-mgf1-sha256' => CKM_SHA256,
        'rsa-pkcs1-oaep-mgf1-sha384' => CKM_SHA384,
        'rsa-pkcs1-oaep-mgf1-sha512' => CKM_SHA512,
    ];

    private const array MGF1_MAP = [
        'rsa-pkcs1-oaep-mgf1-sha1'   => CKG_MGF1_SHA1,
        'rsa-pkcs1-oaep-mgf1-sha224' => CKG_MGF1_SHA224,
        'rsa-pkcs1-oaep-mgf1-sha256' => CKG_MGF1_SHA256,
        'rsa-pkcs1-oaep-mgf1-sha384' => CKG_MGF1_SHA384,
        'rsa-pkcs1-oaep-mgf1-sha512' => CKG_MGF1_SHA512,
    ];

    public function __construct(private readonly BackendGroupConfig $config)
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
            $this->loadPublicKeyData($this->ensureSession());
        }

        assert($this->publicKeyFingerprint !== null);

        return $this->publicKeyFingerprint;
    }

    private function getModulusBytes(): int
    {
        if ($this->modulusBytes === null) {
            $this->loadPublicKeyData($this->ensureSession());
        }

        assert($this->modulusBytes !== null);

        return $this->modulusBytes;
    }

    public function decrypt(string $ciphertext, string $algorithm, string|null $label = null): string
    {
        if (strlen($ciphertext) !== $this->getModulusBytes()) {
            throw new InvalidRequestException(sprintf(
                'Ciphertext length %d does not match modulus length %d',
                strlen($ciphertext),
                $this->getModulusBytes(),
            ));
        }

        $privateKey = $this->ensurePrivateKey();

        $mechanismType = self::MECHANISM_MAP[$algorithm]
            ?? throw new BackendException(sprintf('Unsupported algorithm: %s', $algorithm));

        try {
            $mechanism = $this->buildMechanism($mechanismType, $algorithm, $label);

            return $privateKey->decrypt($mechanism, $ciphertext);
        } catch (Exception $e) {
            if ($this->isSessionError($e)) {
                $this->session    = null;
                $this->privateKey = null;
                $privateKey       = $this->ensurePrivateKey();
                $mechanism        = $this->buildMechanism($mechanismType, $algorithm, $label);

                return $privateKey->decrypt($mechanism, $ciphertext);
            }

            throw new BackendException(sprintf(
                'PKCS#11 decryption failed for backend "%s": %s',
                $this->config->name,
                $e->getMessage(),
            ), $e);
        }
    }

    private function ensurePrivateKey(): Key
    {
        $session = $this->ensureSession();
        if ($this->privateKey === null) {
            $this->privateKey = $this->findPrivateKey($session);
        }

        return $this->privateKey;
    }

    private function buildMechanism(int $mechanismType, string $algorithm, string|null $label): Mechanism
    {
        if ($mechanismType === CKM_RSA_PKCS_OAEP) {
            $hashAlg    = self::OAEP_HASH_MAP[$algorithm];
            $mgf1Alg    = self::MGF1_MAP[$algorithm];
            $oaepParams = new RsaOaepParams($hashAlg, $mgf1Alg, $label ?? '');

            return new Mechanism($mechanismType, $oaepParams);
        }

        return new Mechanism($mechanismType);
    }

    private function ensureSession(): Session
    {
        if ($this->session !== null) {
            return $this->session;
        }

        if ($this->config->pkcs11Lib === null) {
            throw new BackendException(sprintf('pkcs11_lib not configured for backend "%s"', $this->config->name));
        }

        foreach ($this->config->environment as $key => $value) {
            putenv($key . '=' . $value);
        }

        try {
            $module = Pkcs11ModuleCache::get($this->config->pkcs11Lib);

            $slotList = $module->getSlotList();
            $slotId   = $slotList[$this->config->pkcs11Slot]
                ?? throw new BackendException(sprintf('Slot %d not found', $this->config->pkcs11Slot));

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

            $this->session    = $session;
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
                'No private key found in PKCS#11 backend "%s"',
                $this->config->name,
            ));
        }

        return $objects[0];
    }

    private function loadPublicKeyData(Session $session): void
    {
        $template = [
            CKA_CLASS    => CKO_PUBLIC_KEY,
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
                'No public key found for fingerprint in backend "%s"',
                $this->config->name,
            ));
        }

        $attrs = $objects[0]->getAttributeValue([CKA_MODULUS]);

        $this->publicKeyFingerprint = hash('sha256', $attrs[CKA_MODULUS]);
        $this->modulusBytes         = strlen($attrs[CKA_MODULUS]);
    }

    private function isSessionError(Exception $e): bool
    {
        $code = $e->getCode();

        return in_array($code, [0x000000B0, 0x000000B3, 0x00000030], true);
    }
}
