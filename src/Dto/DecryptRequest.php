<?php

declare(strict_types=1);

namespace App\Dto;

use App\Validator as AppAssert;
use Symfony\Component\Serializer\Attribute\SerializedName;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

use function base64_decode;
use function in_array;
use function sprintf;
use function strlen;

final class DecryptRequest
{
    public const array ALGORITHMS = [
        'rsa-pkcs1-v1_5',
        'rsa-pkcs1-oaep-mgf1-sha1',
        'rsa-pkcs1-oaep-mgf1-sha224',
        'rsa-pkcs1-oaep-mgf1-sha256',
        'rsa-pkcs1-oaep-mgf1-sha384',
        'rsa-pkcs1-oaep-mgf1-sha512',
    ];

    private const array OAEP_ALGORITHMS = [
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
    #[SerializedName('encrypted_data')]
    public string $encryptedData = '';

    #[AppAssert\Base64]
    public string|null $label = null;

    #[Assert\Callback]
    public function validateRequest(ExecutionContextInterface $context): void
    {
        // Validate encrypted_data length (128-1024 bytes decoded)
        if ($this->encryptedData !== '') {
            $decoded = base64_decode($this->encryptedData, true);
            if ($decoded !== false) {
                $len = strlen($decoded);
                if ($len < 128 || $len > 1024) {
                    $context->buildViolation(sprintf(
                        'Encrypted data must be 128-1024 bytes, got %d bytes.',
                        $len,
                    ))
                        ->atPath('encryptedData')
                        ->addViolation();
                }
            }
        }

        // Label is only valid for OAEP algorithms
        if ($this->label === null || in_array($this->algorithm, self::OAEP_ALGORITHMS, true)) {
            return;
        }

        $context->buildViolation('Label is only allowed for OAEP algorithms.')
            ->atPath('label')
            ->addViolation();
    }
}
