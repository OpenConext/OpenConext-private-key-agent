<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Integration\Backend;

use OpenConext\PrivateKeyAgent\Backend\OpenSslBackend;
use OpenConext\PrivateKeyAgent\Crypto\DigestInfoBuilder;
use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Exception\OpenSSLException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

use function assert;
use function file_get_contents;
use function file_put_contents;
use function hash;
use function is_array;
use function openssl_pkey_export_to_file;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_new;
use function openssl_public_decrypt;
use function openssl_public_encrypt;
use function str_repeat;
use function strlen;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

class OpenSslBackendTest extends TestCase
{
    private static string $keyPath;
    private static int $modulusBytes;

    public static function setUpBeforeClass(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair, 'Failed to generate RSA key pair');
        self::$keyPath = tempnam(sys_get_temp_dir(), 'rsa_') . '.pem';
        openssl_pkey_export_to_file($keyPair, self::$keyPath);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        self::$modulusBytes = strlen($details['rsa']['n']);
    }

    public static function tearDownAfterClass(): void
    {
        @unlink(self::$keyPath);
    }

    private function getPublicKey(): string
    {
        $pem        = file_get_contents(self::$keyPath);
        $privateKey = openssl_pkey_get_private((string) $pem);
        assert($privateKey !== false);
        $details = openssl_pkey_get_details($privateKey);
        assert(is_array($details));

        return (string) $details['key'];
    }

    public function testGetNameReturnsConfiguredName(): void
    {
        $backend = new OpenSslBackend('test-key', self::$keyPath);
        $this->assertSame('test-key', $backend->getName());
    }

    public function testIsHealthyReturnsTrue(): void
    {
        $backend = new OpenSslBackend('test-key', self::$keyPath);
        $this->assertTrue($backend->isHealthy());
    }

    #[DataProvider('signAlgorithmProvider')]
    public function testSignRoundtrip(string $algorithm, string $digest): void
    {
        $backend   = new OpenSslBackend('test-key', self::$keyPath);
        $rawHash   = hash($digest, 'test-message', true);
        $signature = $backend->sign($rawHash, $algorithm);

        $this->assertSame(self::$modulusBytes, strlen($signature));

        $decrypted = '';
        $result    = openssl_public_decrypt($signature, $decrypted, $this->getPublicKey(), OPENSSL_PKCS1_PADDING);
        $this->assertTrue($result, 'Signature verification failed');
        $this->assertSame(DigestInfoBuilder::prepend($rawHash, $algorithm), $decrypted);
    }

    /** @return array<string, array{string, string}> */
    public static function signAlgorithmProvider(): array
    {
        return [
            'sha1'   => [SigningAlgorithm::RSA_PKCS1_V1_5_SHA1,   'sha1'],
            'sha256' => [SigningAlgorithm::RSA_PKCS1_V1_5_SHA256, 'sha256'],
            'sha384' => [SigningAlgorithm::RSA_PKCS1_V1_5_SHA384, 'sha384'],
            'sha512' => [SigningAlgorithm::RSA_PKCS1_V1_5_SHA512, 'sha512'],
        ];
    }

    public function testDecryptRoundtripWithPkcs1(): void
    {
        $backend    = new OpenSslBackend('test-key', self::$keyPath);
        $plaintext  = 'hello world';
        $ciphertext = '';
        openssl_public_encrypt($plaintext, $ciphertext, $this->getPublicKey(), OPENSSL_PKCS1_PADDING);

        $result = $backend->decrypt($ciphertext, EncryptionAlgorithm::RSA_PKCS1_V1_5);
        $this->assertSame($plaintext, $result);
    }

    public function testDecryptRoundtripWithOaepSha1(): void
    {
        $backend    = new OpenSslBackend('test-key', self::$keyPath);
        $plaintext  = 'secret message';
        $ciphertext = '';
        openssl_public_encrypt($plaintext, $ciphertext, $this->getPublicKey(), OPENSSL_PKCS1_OAEP_PADDING);

        $result = $backend->decrypt($ciphertext, EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA1);
        $this->assertSame($plaintext, $result);
    }

    public function testDecryptThrowsOnWrongCiphertextLength(): void
    {
        $backend = new OpenSslBackend('test-key', self::$keyPath);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Ciphertext length');
        $backend->decrypt(str_repeat("\x00", 10), 'rsa-pkcs1-v1_5');
    }

    public function testDecryptThrowsOnUnsupportedAlgorithm(): void
    {
        $backend = new OpenSslBackend('test-key', self::$keyPath);

        $this->expectException(BackendException::class);
        $this->expectExceptionMessage('Unsupported algorithm');
        $backend->decrypt(str_repeat("\x00", self::$modulusBytes), 'rsa-unknown-algo');
    }

    public function testConstructorThrowsOnInvalidKeyContent(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'pem_') . '.pem';
        file_put_contents($tmpFile, 'not-a-valid-pem');

        try {
            $this->expectException(OpenSSLException::class);
            $this->expectExceptionMessage('Invalid private key');
            new OpenSslBackend('bad-key', $tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testConstructorThrowsOnMissingKeyFile(): void
    {
        $this->expectException(BackendException::class);
        $this->expectExceptionMessage('Cannot read key file');
        new OpenSslBackend('bad-key', '/nonexistent/path/to/key.pem');
    }

    public function testConstructorThrowsOnNonRsaKey(): void
    {
        $ecKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($ecKey);
        $tmpFile = tempnam(sys_get_temp_dir(), 'ec_') . '.pem';
        openssl_pkey_export_to_file($ecKey, $tmpFile);

        try {
            $this->expectException(BackendException::class);
            $this->expectExceptionMessage('Non-RSA key loaded');
            new OpenSslBackend('ec-key', $tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testSignThrowsOpenSslExceptionWhenDataTooLargeForKey(): void
    {
        $smallKey = openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($smallKey === false) {
            $this->markTestSkipped('Cannot generate 512-bit RSA key (may be blocked by OpenSSL policy)');
        }

        $tmpFile = tempnam(sys_get_temp_dir(), 'small_rsa_') . '.pem';
        openssl_pkey_export_to_file($smallKey, $tmpFile);

        $backend = null;
        try {
            $backend = new OpenSslBackend('small-key', $tmpFile);
        } catch (Throwable) {
            @unlink($tmpFile);
            $this->markTestSkipped('Cannot create OpenSslBackend with 512-bit key in this environment');
        }

        $rawHash = hash('sha384', 'test', true);

        $this->expectException(OpenSSLException::class);
        $this->expectExceptionMessage('OpenSSL signing failed');

        try {
            $backend->sign($rawHash, SigningAlgorithm::RSA_PKCS1_V1_5_SHA384);
        } finally {
            @unlink($tmpFile);
        }
    }

    #[DataProvider('oaepSha2AlgorithmProvider')]
    public function testDecryptRoundtripWithOaepSha2(string $algorithm, string $digest): void
    {
        $backend    = new OpenSslBackend('test-key', self::$keyPath);
        $plaintext  = 'secret-sha2-message';
        $ciphertext = '';
        $encrypted  = openssl_public_encrypt($plaintext, $ciphertext, $this->getPublicKey(), OPENSSL_PKCS1_OAEP_PADDING, digest_algo: $digest);
        self::assertTrue($encrypted, 'openssl_public_encrypt with digest_algo failed');

        $result = $backend->decrypt($ciphertext, $algorithm);
        $this->assertSame($plaintext, $result);
    }

    /** @return array<string, array{string, string}> */
    public static function oaepSha2AlgorithmProvider(): array
    {
        return [
            'sha224' => [EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA224, 'sha224'],
            'sha256' => [EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA256, 'sha256'],
            'sha384' => [EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA384, 'sha384'],
            'sha512' => [EncryptionAlgorithm::RSA_PKCS1_OAEP_MGF1_SHA512, 'sha512'],
        ];
    }
}
