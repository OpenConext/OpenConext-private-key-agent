<?php

declare(strict_types=1);

namespace App\Tests\Integration\Backend;

use App\Backend\OpenSslDecryptionBackend;
use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function hash;
use function openssl_pkey_export_to_file;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function openssl_public_encrypt;
use function random_bytes;
use function str_repeat;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

class OpenSslDecryptionBackendTest extends TestCase
{
    private static string $keyPath;
    private static OpenSSLAsymmetricKey $publicKey;
    private static string $modulus;

    public static function setUpBeforeClass(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair, 'Failed to generate RSA key pair');
        self::$keyPath = tempnam(sys_get_temp_dir(), 'rsa_') . '.pem';
        openssl_pkey_export_to_file($keyPair, self::$keyPath);

        $details = openssl_pkey_get_details($keyPair);
        self::assertNotFalse($details, 'Failed to get key details');
        $publicKey = openssl_pkey_get_public($details['key']);
        self::assertNotFalse($publicKey, 'Failed to get public key');
        self::$publicKey = $publicKey;
        self::$modulus   = $details['rsa']['n'];
    }

    public static function tearDownAfterClass(): void
    {
        if (! file_exists(self::$keyPath)) {
            return;
        }

        unlink(self::$keyPath);
    }

    private function createBackend(): OpenSslDecryptionBackend
    {
        $config = new BackendGroupConfig(name: 'test-ssl', type: 'openssl', keyPath: self::$keyPath);

        return new OpenSslDecryptionBackend($config);
    }

    public function testDecryptPkcs1v15(): void
    {
        $plaintext = 'Hello, World!';
        $encrypted = '';
        openssl_public_encrypt($plaintext, $encrypted, self::$publicKey, OPENSSL_PKCS1_PADDING);

        $backend = $this->createBackend();
        $result  = $backend->decrypt($encrypted, 'rsa-pkcs1-v1_5');

        $this->assertSame($plaintext, $result);
    }

    public function testDecryptOaepSha1(): void
    {
        $plaintext = 'OAEP test';
        $encrypted = '';
        openssl_public_encrypt($plaintext, $encrypted, self::$publicKey, OPENSSL_PKCS1_OAEP_PADDING);

        $backend = $this->createBackend();
        $result  = $backend->decrypt($encrypted, 'rsa-pkcs1-oaep-mgf1-sha1');

        $this->assertSame($plaintext, $result);
    }

    public function testDecryptOaepSha256(): void
    {
        $plaintext = 'OAEP-256 test';
        $encrypted = '';
        openssl_public_encrypt($plaintext, $encrypted, self::$publicKey, OPENSSL_PKCS1_OAEP_PADDING, digest_algo: 'sha256');

        $backend = $this->createBackend();
        $result  = $backend->decrypt($encrypted, 'rsa-pkcs1-oaep-mgf1-sha256');

        $this->assertSame($plaintext, $result);
    }

    public function testDecryptWithInvalidCiphertextThrows(): void
    {
        $backend = $this->createBackend();

        // OAEP decryption fails reliably on bad ciphertext (OpenSSL 3.x implicit rejection
        // prevents PKCS#1 v1.5 from failing, but OAEP does not have this mechanism).
        $this->expectException(BackendException::class);
        $backend->decrypt(random_bytes(256), 'rsa-pkcs1-oaep-mgf1-sha1');
    }

    public function testIsHealthyReturnsTrue(): void
    {
        $backend = $this->createBackend();
        $this->assertTrue($backend->isHealthy());
    }

    public function testGetNameReturnsConfiguredName(): void
    {
        $backend = $this->createBackend();
        $this->assertSame('test-ssl', $backend->getName());
    }

    public function testGetPublicKeyFingerprint(): void
    {
        $backend     = $this->createBackend();
        $fingerprint = $backend->getPublicKeyFingerprint();
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $fingerprint);
        $this->assertSame(hash('sha256', self::$modulus), $fingerprint);
    }

    public function testDecryptRejectsWrongLengthCiphertext(): void
    {
        $backend = $this->createBackend();

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Ciphertext length');
        // Wrong length: 10 bytes instead of 256 (2048-bit modulus)
        $backend->decrypt(str_repeat("\x00", 10), 'rsa-pkcs1-v1_5');
    }

    public function testThrowsOnNonRsaKey(): void
    {
        $ecKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => 'prime256v1',
        ]);
        self::assertNotFalse($ecKey, 'Failed to generate EC key pair');
        $ecKeyPath = tempnam(sys_get_temp_dir(), 'ec_') . '.pem';
        openssl_pkey_export_to_file($ecKey, $ecKeyPath);

        try {
            $this->expectException(BackendException::class);
            $this->expectExceptionMessage('Non-RSA key loaded from:');
            new OpenSslDecryptionBackend(
                new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: $ecKeyPath),
            );
        } finally {
            @unlink($ecKeyPath);
        }
    }
}
