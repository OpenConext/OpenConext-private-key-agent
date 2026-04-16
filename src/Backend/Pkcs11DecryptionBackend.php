<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use Pkcs11\Exception;
use Pkcs11\Mechanism;
use Pkcs11\RsaOaepParams;
use Pkcs11\Session;
use Psr\Log\LoggerInterface;
use Throwable;

use function assert;
use function count;
use function extension_loaded;
use function hash;
use function hex2bin;
use function sprintf;
use function strlen;

use const Pkcs11\CKA_CLASS;
use const Pkcs11\CKA_ID;
use const Pkcs11\CKA_KEY_TYPE;
use const Pkcs11\CKA_LABEL;
use const Pkcs11\CKA_MODULUS;
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
use const Pkcs11\CKO_PUBLIC_KEY;

final class Pkcs11DecryptionBackend implements DecryptionBackendInterface
{
    private string|null $publicKeyFingerprint = null;
    private int|null $modulusBytes            = null;

    private readonly Pkcs11SessionManager $sessionManager;

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

    public function __construct(
        private readonly BackendGroupConfig $config,
        private readonly LoggerInterface $logger,
    ) {
        if (! extension_loaded('pkcs11')) {
            throw new BackendException('pkcs11 PHP extension is not loaded');
        }

        $this->sessionManager = new Pkcs11SessionManager($config, $logger);
    }

    public function getName(): string
    {
        return $this->config->name;
    }

    public function isHealthy(): bool
    {
        try {
            $this->sessionManager->ensureSession()->getInfo();

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    public function getPublicKeyFingerprint(): string
    {
        if ($this->publicKeyFingerprint === null) {
            $this->loadPublicKeyData($this->sessionManager->ensureSession());
        }

        assert($this->publicKeyFingerprint !== null);

        return $this->publicKeyFingerprint;
    }

    private function getModulusBytes(): int
    {
        if ($this->modulusBytes === null) {
            $this->loadPublicKeyData($this->sessionManager->ensureSession());
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

        $privateKey = $this->sessionManager->ensurePrivateKey();

        $mechanismType = self::MECHANISM_MAP[$algorithm]
            ?? throw new BackendException(sprintf('Unsupported algorithm: %s', $algorithm));

        try {
            $mechanism = $this->buildMechanism($mechanismType, $algorithm, $label);

            return $privateKey->decrypt($mechanism, $ciphertext);
        } catch (Exception $e) {
            if ($this->sessionManager->isSessionError($e)) {
                $this->logger->warning(
                    'PKCS#11 session error during decryption, reconnecting',
                    ['backend' => $this->config->name, 'code' => $e->getCode()],
                );
                $this->invalidateSession();
                $privateKey = $this->sessionManager->ensurePrivateKey();
                $mechanism  = $this->buildMechanism($mechanismType, $algorithm, $label);

                try {
                    return $privateKey->decrypt($mechanism, $ciphertext);
                } catch (Exception $retryEx) {
                    throw new BackendException(sprintf(
                        'PKCS#11 decryption failed for backend "%s" after session recovery: %s',
                        $this->config->name,
                        $retryEx->getMessage(),
                    ), $retryEx);
                }
            }

            throw new BackendException(sprintf(
                'PKCS#11 decryption failed for backend "%s": %s',
                $this->config->name,
                $e->getMessage(),
            ), $e);
        }
    }

    private function invalidateSession(): void
    {
        $this->sessionManager->invalidateSession();
        $this->publicKeyFingerprint = null;
        $this->modulusBytes         = null;
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
}
