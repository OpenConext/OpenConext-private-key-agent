<?php

declare(strict_types=1);

namespace App\Tests\Integration\Backend;

use App\Backend\OpenSslSigningBackend;
use App\Config\BackendGroupConfig;
use App\Exception\BackendException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function hash;
use function openssl_pkey_export_to_file;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function openssl_verify;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_ALGO_SHA1;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

class OpenSslSigningBackendTest extends TestCase
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

    private function createBackend(): OpenSslSigningBackend
    {
        $config = new BackendGroupConfig(name: 'test-ssl', type: 'openssl', keyPath: self::$keyPath);

        return new OpenSslSigningBackend($config);
    }

    public function testSignSha256(): void
    {
        $backend   = $this->createBackend();
        $hash      = hash('sha256', 'test data', true);
        $signature = $backend->sign($hash, 'rsa-pkcs1-v1_5-sha256');

        $result = openssl_verify('test data', $signature, self::$publicKey, OPENSSL_ALGO_SHA256);
        $this->assertSame(1, $result, 'Signature verification failed');
    }

    public function testSignSha1(): void
    {
        $backend   = $this->createBackend();
        $hash      = hash('sha1', 'test data', true);
        $signature = $backend->sign($hash, 'rsa-pkcs1-v1_5-sha1');

        $result = openssl_verify('test data', $signature, self::$publicKey, OPENSSL_ALGO_SHA1);
        $this->assertSame(1, $result);
    }

    public function testSignSha384(): void
    {
        $backend   = $this->createBackend();
        $hash      = hash('sha384', 'test data', true);
        $signature = $backend->sign($hash, 'rsa-pkcs1-v1_5-sha384');

        $result = openssl_verify('test data', $signature, self::$publicKey, OPENSSL_ALGO_SHA384);
        $this->assertSame(1, $result);
    }

    public function testSignSha512(): void
    {
        $backend   = $this->createBackend();
        $hash      = hash('sha512', 'test data', true);
        $signature = $backend->sign($hash, 'rsa-pkcs1-v1_5-sha512');

        $result = openssl_verify('test data', $signature, self::$publicKey, OPENSSL_ALGO_SHA512);
        $this->assertSame(1, $result);
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

    public function testSignWithInvalidKeyPathThrows(): void
    {
        $config = new BackendGroupConfig(name: 'bad', type: 'openssl', keyPath: '/nonexistent/key.pem');
        $this->expectException(BackendException::class);
        new OpenSslSigningBackend($config);
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
            new OpenSslSigningBackend(
                new BackendGroupConfig(name: 'test', type: 'openssl', keyPath: $ecKeyPath),
            );
        } finally {
            @unlink($ecKeyPath);
        }
    }
}
