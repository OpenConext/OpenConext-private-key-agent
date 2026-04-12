<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use OpenSSLAsymmetricKey;

use function file_get_contents;
use function hash;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_private_decrypt;
use function sprintf;
use function strlen;

use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

final class OpenSslDecryptionBackend implements DecryptionBackendInterface
{
    private OpenSSLAsymmetricKey $privateKey;
    private string $publicKeyFingerprint;
    private int $modulusBytes;

    private const array ALGORITHM_MAP = [
        'rsa-pkcs1-v1_5'             => ['padding' => OPENSSL_PKCS1_PADDING,      'digest' => null],
        'rsa-pkcs1-oaep-mgf1-sha1'   => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha1'],
        'rsa-pkcs1-oaep-mgf1-sha224' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha224'],
        'rsa-pkcs1-oaep-mgf1-sha256' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha256'],
        'rsa-pkcs1-oaep-mgf1-sha384' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha384'],
        'rsa-pkcs1-oaep-mgf1-sha512' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha512'],
    ];

    public function __construct(
        private readonly BackendGroupConfig $config,
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
        $this->modulusBytes         = strlen($details['rsa']['n']);
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

    public function decrypt(string $ciphertext, string $algorithm, string|null $label = null): string
    {
        if (strlen($ciphertext) !== $this->modulusBytes) {
            throw new InvalidRequestException(sprintf(
                'Ciphertext length %d does not match modulus length %d',
                strlen($ciphertext),
                $this->modulusBytes,
            ));
        }

        $spec = self::ALGORITHM_MAP[$algorithm] ?? null;
        if ($spec === null) {
            throw new BackendException(sprintf('Unsupported algorithm: %s', $algorithm));
        }

        $decrypted = '';

        // PHP 8.5+ supports digest_algo named parameter for OAEP with SHA-2
        if ($spec['digest'] !== null && $spec['digest'] !== 'sha1') {
            $result = openssl_private_decrypt(
                $ciphertext,
                $decrypted,
                $this->privateKey,
                $spec['padding'],
                digest_algo: $spec['digest'],
            );
        } else {
            $result = openssl_private_decrypt(
                $ciphertext,
                $decrypted,
                $this->privateKey,
                $spec['padding'],
            );
        }

        if ($result === false) {
            throw new BackendException(sprintf(
                'OpenSSL decryption failed for backend "%s": %s',
                $this->config->name,
                openssl_error_string() ?: 'unknown error',
            ));
        }

        return $decrypted;
    }
}
