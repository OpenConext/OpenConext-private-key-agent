<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Backend;

use OpenConext\PrivateKeyAgent\Crypto\DigestInfoBuilder;
use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Exception\OpenSSLException;
use OpenSSLAsymmetricKey;

use function file_get_contents;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_private_decrypt;
use function openssl_private_encrypt;
use function sprintf;
use function strlen;

use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

final class OpenSslBackend implements SigningBackendInterface, DecryptionBackendInterface
{
    private OpenSSLAsymmetricKey $privateKey;
    private int $modulusBytes;

    private const array ALGORITHM_MAP = [
        EncryptionAlgorithm::RSA_PKCS1_V1_5            => ['padding' => OPENSSL_PKCS1_PADDING,      'digest' => null],
        EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA1   => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha1'],
        EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA224 => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha224'],
        EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA256 => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha256'],
        EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA384 => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha384'],
        EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA512 => ['padding' => OPENSSL_PKCS1_OAEP_PADDING, 'digest' => 'sha512'],
    ];

    public function __construct(
        private readonly string $name,
        string $keyPath,
    ) {
        $keyContent = @file_get_contents($keyPath);
        if ($keyContent === false) {
            throw new BackendException(sprintf('Cannot read key file: %s', $keyPath));
        }

        self::drainOpenSslErrorQueue();

        $key = openssl_pkey_get_private($keyContent);
        if ($key === false) {
            throw new OpenSSLException(sprintf('Invalid private key in: %s', $keyPath));
        }

        $this->privateKey = $key;

        self::drainOpenSslErrorQueue();

        $details = openssl_pkey_get_details($this->privateKey);
        if ($details === false) {
            throw new OpenSSLException(sprintf('Failed to read key details from: %s', $keyPath));
        }

        if (! isset($details['rsa']['n'])) {
            throw new BackendException(sprintf('Non-RSA key loaded from: %s', $keyPath));
        }

        $this->modulusBytes = strlen($details['rsa']['n']);
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function isHealthy(): bool
    {
        if (openssl_pkey_get_details($this->privateKey) === false) {
            self::drainOpenSslErrorQueue();

            return false;
        }

        return true;
    }

    public function sign(string $hash, string $algorithm): string
    {
        $digestInfo = DigestInfoBuilder::prepend($hash, $algorithm);

        $signature = '';

        self::drainOpenSslErrorQueue();

        $result = openssl_private_encrypt($digestInfo, $signature, $this->privateKey, OPENSSL_PKCS1_PADDING);

        if ($result === false) {
            throw new OpenSSLException(sprintf('OpenSSL signing failed for key "%s"', $this->name));
        }

        return $signature;
    }

    public function decrypt(string $ciphertext, string $algorithm): string
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

        self::drainOpenSslErrorQueue();

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
            throw new OpenSSLException(sprintf('OpenSSL decryption failed for key "%s"', $this->name));
        }

        return $decrypted;
    }

    private static function drainOpenSslErrorQueue(): void
    {
        while (openssl_error_string() !== false) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        }
    }
}
