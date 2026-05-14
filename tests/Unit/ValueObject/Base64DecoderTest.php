<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\ValueObject;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\ValueObject\Base64Decoder;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function random_bytes;

class Base64DecoderTest extends TestCase
{
    public function testDecodesValidBase64(): void
    {
        $raw     = random_bytes(32);
        $encoded = base64_encode($raw);

        $this->assertSame($raw, Base64Decoder::decode($encoded, 'test'));
    }

    public function testDecodesBase64WithPadding(): void
    {
        $raw     = random_bytes(10); // produces padding '=='
        $encoded = base64_encode($raw);

        $this->assertSame($raw, Base64Decoder::decode($encoded, 'field'));
    }

    public function testThrowsOnEmptyString(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The hash field must not be empty.');

        Base64Decoder::decode('', 'hash');
    }

    public function testThrowsOnInvalidCharacters(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded payload.');

        Base64Decoder::decode('not valid base64!!!', 'payload');
    }

    public function testThrowsOnInvalidBase64WithNewlines(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid base64-encoded data.');

        Base64Decoder::decode("SGVsbG8=\nV29ybGQ=", 'data');
    }

    public function testFieldNameAppearsInErrorMessage(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The encrypted_data field must not be empty.');

        Base64Decoder::decode('', 'encrypted_data');
    }
}
