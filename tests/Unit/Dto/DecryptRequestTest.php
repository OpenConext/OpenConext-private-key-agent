<?php

declare(strict_types=1);

namespace App\Tests\Unit\Dto;

use App\Dto\DecryptRequest;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Validator\ValidatorInterface;

use function base64_encode;
use function random_bytes;

class DecryptRequestTest extends TestCase
{
    private ValidatorInterface $validator;

    protected function setUp(): void
    {
        $this->validator = Validation::createValidatorBuilder()
            ->enableAttributeMapping()
            ->getValidator();
    }

    public function testValidOaepSha256Request(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'rsa-pkcs1-oaep-mgf1-sha256';
        $request->encryptedData = base64_encode(random_bytes(256));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }

    public function testValidPkcs1v15Request(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'rsa-pkcs1-v1_5';
        $request->encryptedData = base64_encode(random_bytes(256));

        $violations = $this->validator->validate($request);
        $this->assertCount(0, $violations, (string) $violations);
    }

    public function testInvalidAlgorithmFails(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'aes-cbc';
        $request->encryptedData = base64_encode(random_bytes(256));

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testMissingEncryptedDataFails(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'rsa-pkcs1-v1_5';
        $request->encryptedData = '';

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testEncryptedDataTooSmallFails(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'rsa-pkcs1-v1_5';
        $request->encryptedData = base64_encode(random_bytes(64)); // < 128 bytes

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }

    public function testEncryptedDataTooLargeFails(): void
    {
        $request                = new DecryptRequest();
        $request->algorithm     = 'rsa-pkcs1-v1_5';
        $request->encryptedData = base64_encode(random_bytes(2048)); // > 1024 bytes

        $violations = $this->validator->validate($request);
        $this->assertGreaterThan(0, $violations->count());
    }
}
