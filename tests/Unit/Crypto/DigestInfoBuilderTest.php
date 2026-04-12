<?php

declare(strict_types=1);

namespace App\Tests\Unit\Crypto;

use App\Crypto\DigestInfoBuilder;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

use function hex2bin;
use function random_bytes;

class DigestInfoBuilderTest extends TestCase
{
    public function testPrependSha1(): void
    {
        $hash   = random_bytes(20);
        $result = DigestInfoBuilder::prepend($hash, 'rsa-pkcs1-v1_5-sha1');

        // SHA-1 DigestInfo prefix: 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
        $expectedPrefix = hex2bin('3021300906052b0e03021a05000414');
        $this->assertSame($expectedPrefix . $hash, $result);
    }

    public function testPrependSha256(): void
    {
        $hash   = random_bytes(32);
        $result = DigestInfoBuilder::prepend($hash, 'rsa-pkcs1-v1_5-sha256');

        // SHA-256 DigestInfo prefix: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        $expectedPrefix = hex2bin('3031300d060960864801650304020105000420');
        $this->assertSame($expectedPrefix . $hash, $result);
    }

    public function testPrependSha384(): void
    {
        $hash   = random_bytes(48);
        $result = DigestInfoBuilder::prepend($hash, 'rsa-pkcs1-v1_5-sha384');

        // SHA-384 DigestInfo prefix: 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
        $expectedPrefix = hex2bin('3041300d060960864801650304020205000430');
        $this->assertSame($expectedPrefix . $hash, $result);
    }

    public function testPrependSha512(): void
    {
        $hash   = random_bytes(64);
        $result = DigestInfoBuilder::prepend($hash, 'rsa-pkcs1-v1_5-sha512');

        // SHA-512 DigestInfo prefix: 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
        $expectedPrefix = hex2bin('3051300d060960864801650304020305000440');
        $this->assertSame($expectedPrefix . $hash, $result);
    }

    public function testPrependThrowsOnUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm');
        DigestInfoBuilder::prepend(random_bytes(32), 'rsa-pkcs1-v1_5-md5');
    }
}
