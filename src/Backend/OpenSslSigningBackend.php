<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Crypto\DigestInfoBuilder;
use App\Exception\BackendException;
use OpenSSLAsymmetricKey;

use Psr\Log\LoggerInterface;
use function file_get_contents;
use function hash;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_private_encrypt;
use function sprintf;

use const OPENSSL_PKCS1_PADDING;

final class OpenSslSigningBackend implements SigningBackendInterface
{
    private OpenSSLAsymmetricKey $privateKey;
    private string $publicKeyFingerprint;

    public function __construct(
        private readonly BackendGroupConfig $config,
        private readonly LoggerInterface $logger,
    ) {
        $keyContent = @file_get_contents($config->keyPath ?? '');
        if ($keyContent === false) {
            throw new BackendException(sprintf('Cannot read key file: %s', $config->keyPath));
        }

        $key = openssl_pkey_get_private($keyContent);
        if ($key === false) {
            throw new BackendException(sprintf('Invalid private key in: %s', $config->keyPath));
        }

        $this->privateKey = $key;

        $details = openssl_pkey_get_details($this->privateKey);
        if ($details === false) {
            throw new BackendException(sprintf('Failed to read key details from: %s', $config->keyPath));
        }

        if (! isset($details['rsa']['n'])) {
            throw new BackendException(sprintf('Non-RSA key loaded from: %s', $config->keyPath));
        }

        $this->publicKeyFingerprint = hash('sha256', $details['rsa']['n']);
    }

    public function getName(): string
    {
        return $this->config->name;
    }

    public function isHealthy(): bool
    {
        return true;
    }

    public function getPublicKeyFingerprint(): string
    {
        return $this->publicKeyFingerprint;
    }

    public function sign(string $hash, string $algorithm): string
    {
        $digestInfo = DigestInfoBuilder::prepend($hash, $algorithm);

        $signature = '';
        $result    = openssl_private_encrypt($digestInfo, $signature, $this->privateKey, OPENSSL_PKCS1_PADDING);

        if ($result === false) {
            throw new BackendException(sprintf(
                'OpenSSL signing failed for backend "%s": %s',
                $this->config->name,
                openssl_error_string() ?: 'unknown error',
            ));
        }

        return $signature;
    }
}
