<?php

declare(strict_types=1);

namespace App\Dto;

use App\Validator as AppAssert;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

use function base64_decode;
use function sprintf;
use function strlen;

final class DecryptRequest
{
    private const array ALGORITHMS = [
        'rsa-pkcs1-v1_5',
        'rsa-pkcs1-oaep-mgf1-sha1',
        'rsa-pkcs1-oaep-mgf1-sha224',
        'rsa-pkcs1-oaep-mgf1-sha256',
        'rsa-pkcs1-oaep-mgf1-sha384',
        'rsa-pkcs1-oaep-mgf1-sha512',
    ];

    #[Assert\NotBlank]
    #[Assert\Choice(choices: self::ALGORITHMS, message: 'Invalid decryption algorithm.')]
    public string $algorithm = '';

    #[Assert\NotBlank]
    #[AppAssert\Base64]
    public string $encryptedData = '';

    #[Assert\Callback]
    public function validateRequest(ExecutionContextInterface $context): void
    {
        if ($this->encryptedData === '') {
            return;
        }

        $decoded = base64_decode($this->encryptedData, true);
        if ($decoded === false) {
            return;
        }

        $len = strlen($decoded);
        if ($len >= 128 && $len <= 1024) {
            return;
        }

        $context->buildViolation(sprintf(
            'Encrypted data must be 128-1024 bytes, got %d bytes.',
            $len,
        ))
            ->atPath('encryptedData')
            ->addViolation();
    }
}
