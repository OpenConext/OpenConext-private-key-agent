<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Crypto\DigestInfoBuilder;
use App\Exception\BackendException;
use Pkcs11\Exception;
use Pkcs11\Mechanism;
use Pkcs11\Session;
use Psr\Log\LoggerInterface;
use Throwable;

use function count;
use function extension_loaded;
use function hash;
use function hex2bin;
use function sprintf;

use const Pkcs11\CKA_CLASS;
use const Pkcs11\CKA_ID;
use const Pkcs11\CKA_KEY_TYPE;
use const Pkcs11\CKA_LABEL;
use const Pkcs11\CKA_MODULUS;
use const Pkcs11\CKK_RSA;
use const Pkcs11\CKM_RSA_PKCS;
use const Pkcs11\CKO_PUBLIC_KEY;

final class Pkcs11SigningBackend implements SigningBackendInterface
{
    private string|null $publicKeyFingerprint = null;

    private readonly Pkcs11SessionManager $sessionManager;

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
            $this->publicKeyFingerprint = $this->computeFingerprint($this->sessionManager->ensureSession());
        }

        return $this->publicKeyFingerprint;
    }

    public function sign(string $hash, string $algorithm): string
    {
        $privateKey = $this->sessionManager->ensurePrivateKey();

        $digestInfo = DigestInfoBuilder::prepend($hash, $algorithm);

        try {
            $mechanism = new Mechanism(CKM_RSA_PKCS);

            return $privateKey->sign($mechanism, $digestInfo);
        } catch (Exception $e) {
            if ($this->sessionManager->isSessionError($e)) {
                $this->logger->warning(
                    'PKCS#11 session error during signing, reconnecting',
                    ['backend' => $this->config->name, 'code' => $e->getCode()],
                );
                $this->invalidateSession();
                $privateKey = $this->sessionManager->ensurePrivateKey();
                $mechanism  = new Mechanism(CKM_RSA_PKCS);

                try {
                    return $privateKey->sign($mechanism, $digestInfo);
                } catch (Exception $retryEx) {
                    throw new BackendException(sprintf(
                        'PKCS#11 signing failed for backend "%s" after session recovery: %s',
                        $this->config->name,
                        $retryEx->getMessage(),
                    ), $retryEx);
                }
            }

            throw new BackendException(sprintf(
                'PKCS#11 signing failed for backend "%s": %s',
                $this->config->name,
                $e->getMessage(),
            ), $e);
        }
    }

    private function invalidateSession(): void
    {
        $this->sessionManager->invalidateSession();
        $this->publicKeyFingerprint = null;
    }

    private function computeFingerprint(Session $session): string
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
            throw new BackendException(sprintf('No public key found for fingerprint in backend "%s"', $this->config->name));
        }

        $attrs = $objects[0]->getAttributeValue([CKA_MODULUS]);

        return hash('sha256', $attrs[CKA_MODULUS]);
    }
}
