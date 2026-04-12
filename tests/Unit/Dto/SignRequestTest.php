<?php

declare(strict_types=1);

namespace App\Tests\Unit\Dto;

use App\Dto\SignRequest;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Validator\ValidatorInterface;

use function base64_encode;
use function random_bytes;

class SignRequestTest extends TestCase
{
    private ValidatorInterface $validator;

    protected function setUp(): void
    {
        $this->validator = Validation::createValidatorBuilder()
            ->enableAttributeMapping()
            ->getValidator();
    }

    public function testValidSha256Request(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha256';
        $request->hash      = base64_encode(random_bytes(32));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }

    public function testInvalidAlgorithmFails(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-invalid';
        $request->hash      = base64_encode(random_bytes(32));

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testMissingHashFails(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha256';
        $request->hash      = '';

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testInvalidBase64HashFails(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha256';
        $request->hash      = 'not!!valid!!base64';

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testWrongHashLengthForSha256Fails(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha256';
        $request->hash      = base64_encode(random_bytes(20)); // SHA-1 length, not SHA-256

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testSha1With20BytesPasses(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha1';
        $request->hash      = base64_encode(random_bytes(20));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }

    public function testSha384With48BytesPasses(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha384';
        $request->hash      = base64_encode(random_bytes(48));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }

    public function testSha512With64BytesPasses(): void
    {
        $request            = new SignRequest();
        $request->algorithm = 'rsa-pkcs1-v1_5-sha512';
        $request->hash      = base64_encode(random_bytes(64));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }
}
