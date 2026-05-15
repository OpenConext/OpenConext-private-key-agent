<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Backend;

use OpenConext\PrivateKeyAgent\Crypto\DigestInfoBuilder;
use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
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

    public function sign(string $hash, SigningAlgorithm $algorithm): string
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

    public function decrypt(string $ciphertext, EncryptionAlgorithm $algorithm): string
    {
        if (strlen($ciphertext) !== $this->modulusBytes) {
            throw new InvalidRequestException(sprintf(
                'Ciphertext length %d does not match modulus length %d',
                strlen($ciphertext),
                $this->modulusBytes,
            ));
        }

        [$padding, $digest] = self::decryptionSpec($algorithm);

        $decrypted = '';

        self::drainOpenSslErrorQueue();

        // PHP 8.5+ supports digest_algo named parameter for OAEP with SHA-2
        if ($digest !== null && $digest !== 'sha1') {
            $result = openssl_private_decrypt(
                $ciphertext,
                $decrypted,
                $this->privateKey,
                $padding,
                digest_algo: $digest,
            );
        } else {
            $result = openssl_private_decrypt(
                $ciphertext,
                $decrypted,
                $this->privateKey,
                $padding,
            );
        }

        if ($result === false) {
            throw new OpenSSLException(sprintf('OpenSSL decryption failed for key "%s"', $this->name));
        }

        return $decrypted;
    }

    /** @return array{int, string|null} */
    private static function decryptionSpec(EncryptionAlgorithm $algorithm): array
    {
        return match ($algorithm) {
            EncryptionAlgorithm::RsaPkcs1V15       => [OPENSSL_PKCS1_PADDING, null],
            EncryptionAlgorithm::RsaOaepMgf1Sha1   => [OPENSSL_PKCS1_OAEP_PADDING, 'sha1'],
            EncryptionAlgorithm::RsaOaepMgf1Sha224 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha224'],
            EncryptionAlgorithm::RsaOaepMgf1Sha256 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha256'],
            EncryptionAlgorithm::RsaOaepMgf1Sha384 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha384'],
            EncryptionAlgorithm::RsaOaepMgf1Sha512 => [OPENSSL_PKCS1_OAEP_PADDING, 'sha512'],
        };
    }

    private static function drainOpenSslErrorQueue(): void
    {
        while (openssl_error_string() !== false) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        }
    }
}
