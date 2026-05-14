<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\ValueObject;

use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\ValueObject\SigningInput;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function random_bytes;
use function sprintf;
use function strlen;

class SigningInputTest extends TestCase
{
    public function testValidSha1With20Bytes(): void
    {
        $input = SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA1,
            'hash' => base64_encode(random_bytes(20)),
        ]);

        $this->assertSame(SigningAlgorithm::RSA_PKCS1_V1_5_SHA1, $input->algorithm);
        $this->assertSame(20, strlen($input->hashBytes));
    }

    public function testValidSha256With32Bytes(): void
    {
        $hash  = random_bytes(32);
        $input = SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => base64_encode($hash),
        ]);

        $this->assertSame(SigningAlgorithm::RSA_PKCS1_V1_5_SHA256, $input->algorithm);
        $this->assertSame($hash, $input->hashBytes);
    }

    public function testValidSha384With48Bytes(): void
    {
        $input = SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA384,
            'hash' => base64_encode(random_bytes(48)),
        ]);

        $this->assertSame(48, strlen($input->hashBytes));
    }

    public function testValidSha512With64Bytes(): void
    {
        $input = SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA512,
            'hash' => base64_encode(random_bytes(64)),
        ]);

        $this->assertSame(64, strlen($input->hashBytes));
    }

    public function testUnknownAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid signing algorithm.');

        SigningInput::fromArray([
            'algorithm' => 'rsa-invalid',
            'hash' => base64_encode(random_bytes(32)),
        ]);
    }

    public function testEmptyAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid signing algorithm.');

        SigningInput::fromArray([
            'algorithm' => '',
            'hash' => base64_encode(random_bytes(32)),
        ]);
    }

    public function testHashWithWhitespaceThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded hash.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => "YQ==\n",
        ]);
    }

    public function testHashWithNonBase64CharsThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded hash.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => 'not!!valid!!base64',
        ]);
    }

    public function testHashWithTrailingNewlineThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded hash.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => base64_encode(random_bytes(32)) . "\n",
        ]);
    }

    public function testHashWithUrlSafeCharsThrows(): void
    {
        // URL-safe base64 uses - and _ instead of + and /
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded hash.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => 'dGVzdA-_dGVzdA==',
        ]);
    }

    public function testHashWithMisplacedPaddingThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded hash.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => '=YQ==',
        ]);
    }

    public function testEmptyHashThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field must not be empty.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => '',
        ]);
    }

    public function testWrongHashLengthForSha256Throws(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage(sprintf(
            'Hash length 20 bytes does not match expected 32 bytes for %s.',
            SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
        ));

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => base64_encode(random_bytes(20)), // SHA-1 length
        ]);
    }

    public function testMissingAlgorithmFieldThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field is required.');

        SigningInput::fromArray(['hash' => base64_encode(random_bytes(32))]);
    }

    public function testMissingHashFieldThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field is required.');

        SigningInput::fromArray(['algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256]);
    }

    public function testEmptyObjectThrowsMissingAlgorithm(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field is required.');

        SigningInput::fromArray([]);
    }

    public function testIntegerAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        SigningInput::fromArray([
            'algorithm' => 123,
            'hash' => base64_encode(random_bytes(32)),
        ]);
    }

    public function testArrayAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        SigningInput::fromArray([
            'algorithm' => [],
            'hash' => base64_encode(random_bytes(32)),
        ]);
    }

    public function testNullAlgorithmThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The algorithm field must be a string.');

        SigningInput::fromArray([
            'algorithm' => null,
            'hash' => base64_encode(random_bytes(32)),
        ]);
    }

    public function testIntegerHashThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field must be a string.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => 42,
        ]);
    }

    public function testArrayHashThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field must be a string.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => [],
        ]);
    }

    public function testNullHashThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field must be a string.');

        SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => null,
        ]);
    }

    public function testHashBytesAreDecodedBinary(): void
    {
        $rawBytes = random_bytes(32);
        $input    = SigningInput::fromArray([
            'algorithm' => SigningAlgorithm::RSA_PKCS1_V1_5_SHA256,
            'hash' => base64_encode($rawBytes),
        ]);

        $this->assertSame($rawBytes, $input->hashBytes);
    }
}
