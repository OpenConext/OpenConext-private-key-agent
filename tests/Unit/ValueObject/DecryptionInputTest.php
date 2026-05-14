<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\ValueObject;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\ValueObject\DecryptionInput;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function random_bytes;
use function strlen;

class DecryptionInputTest extends TestCase
{
    public function testValidPkcs1v15With256Bytes(): void
    {
        $ciphertext = random_bytes(256);
        $input      = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode($ciphertext),
        ]);

        $this->assertSame('rsa-pkcs1-v1_5', $input->algorithm);
        $this->assertSame($ciphertext, $input->ciphertextBytes);
    }

    public function testValidOaepSha1(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-oaep-mgf1-sha1',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);

        $this->assertSame('rsa-pkcs1-oaep-mgf1-sha1', $input->algorithm);
    }

    public function testValidOaepSha224(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-oaep-mgf1-sha224',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);

        $this->assertSame('rsa-pkcs1-oaep-mgf1-sha224', $input->algorithm);
    }

    public function testValidOaepSha256(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-oaep-mgf1-sha256',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);

        $this->assertSame('rsa-pkcs1-oaep-mgf1-sha256', $input->algorithm);
    }

    public function testValidOaepSha384(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-oaep-mgf1-sha384',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);

        $this->assertSame('rsa-pkcs1-oaep-mgf1-sha384', $input->algorithm);
    }

    public function testValidOaepSha512(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-oaep-mgf1-sha512',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);

        $this->assertSame('rsa-pkcs1-oaep-mgf1-sha512', $input->algorithm);
    }

    public function testValidMinimumSize128Bytes(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(128)),
        ]);

        $this->assertSame(128, strlen($input->ciphertextBytes));
    }

    public function testValidMaximumSize1024Bytes(): void
    {
        $input = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(1024)),
        ]);

        $this->assertSame(1024, strlen($input->ciphertextBytes));
    }

    public function testUnknownAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid decryption algorithm.');

        DecryptionInput::fromArray([
            'algorithm' => 'aes-cbc',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);
    }

    public function testEmptyAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid decryption algorithm.');

        DecryptionInput::fromArray([
            'algorithm' => '',
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);
    }

    public function testEncryptedDataWithWhitespaceThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded encrypted_data.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => "YQ==\n",
        ]);
    }

    public function testEncryptedDataWithTrailingNewlineThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded encrypted_data.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(256)) . "\n",
        ]);
    }

    public function testEncryptedDataWithUrlSafeCharsThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded encrypted_data.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => 'dGVzdA-_dGVzdA==',
        ]);
    }

    public function testEncryptedDataWithMisplacedPaddingThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded encrypted_data.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => '=dGVzdA==',
        ]);
    }

    public function testEmptyEncryptedDataThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field must not be empty.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => '',
        ]);
    }

    public function testCiphertextTooSmallThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Encrypted data must be 128-1024 bytes, got 64 bytes.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(64)),
        ]);
    }

    public function testCiphertextTooLargeThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Encrypted data must be 128-1024 bytes, got 2048 bytes.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(2048)),
        ]);
    }

    public function testCiphertextJustBelowMinimumThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Encrypted data must be 128-1024 bytes, got 127 bytes.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(127)),
        ]);
    }

    public function testCiphertextJustAboveMaximumThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Encrypted data must be 128-1024 bytes, got 1025 bytes.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode(random_bytes(1025)),
        ]);
    }

    public function testMissingAlgorithmFieldThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field is required.');

        DecryptionInput::fromArray(['encrypted_data' => base64_encode(random_bytes(256))]);
    }

    public function testMissingEncryptedDataFieldThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field is required.');

        DecryptionInput::fromArray(['algorithm' => 'rsa-pkcs1-v1_5']);
    }

    public function testEmptyObjectThrowsMissingAlgorithm(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field is required.');

        DecryptionInput::fromArray([]);
    }

    public function testIntegerAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => 123,
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);
    }

    public function testArrayAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => [],
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);
    }

    public function testNullAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => null,
            'encrypted_data' => base64_encode(random_bytes(256)),
        ]);
    }

    public function testIntegerEncryptedDataThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => 42,
        ]);
    }

    public function testArrayEncryptedDataThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => [],
        ]);
    }

    public function testNullEncryptedDataThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field must be a string.');

        DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => null,
        ]);
    }

    public function testCiphertextBytesAreDecodedBinary(): void
    {
        $rawBytes = random_bytes(256);
        $input    = DecryptionInput::fromArray([
            'algorithm' => 'rsa-pkcs1-v1_5',
            'encrypted_data' => base64_encode($rawBytes),
        ]);

        $this->assertSame($rawBytes, $input->ciphertextBytes);
    }
}
