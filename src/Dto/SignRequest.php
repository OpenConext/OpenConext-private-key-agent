<?php

declare(strict_types=1);

namespace App\Dto;

use App\Validator as AppAssert;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

use function base64_decode;
use function in_array;
use function sprintf;
use function strlen;

final class SignRequest
{
    public const array ALGORITHMS = [
        'rsa-pkcs1-v1_5-sha1',
        'rsa-pkcs1-v1_5-sha256',
        'rsa-pkcs1-v1_5-sha384',
        'rsa-pkcs1-v1_5-sha512',
    ];

    private const array HASH_LENGTHS = [
        'rsa-pkcs1-v1_5-sha1'   => 20,
        'rsa-pkcs1-v1_5-sha256' => 32,
        'rsa-pkcs1-v1_5-sha384' => 48,
        'rsa-pkcs1-v1_5-sha512' => 64,
    ];

    #[Assert\NotBlank]
    #[Assert\Choice(choices: self::ALGORITHMS, message: 'Invalid signing algorithm.')]
    public string $algorithm = '';

    #[Assert\NotBlank]
    #[AppAssert\Base64]
    public string $hash = '';

    #[Assert\Callback]
    public function validateHashLength(ExecutionContextInterface $context): void
    {
        if (! in_array($this->algorithm, self::ALGORITHMS, true)) {
            return; // Algorithm validation will handle this
        }

        if ($this->hash === '') {
            return; // NotBlank will handle this
        }

        $decoded = base64_decode($this->hash, true);
        if ($decoded === false) {
            return; // Base64 validator will handle this
        }

        $expectedLength = self::HASH_LENGTHS[$this->algorithm];
        $actualLength   = strlen($decoded);
        if ($actualLength === $expectedLength) {
            return;
        }

        $context->buildViolation(sprintf(
            'Hash length %d bytes does not match expected %d bytes for %s.',
            $actualLength,
            $expectedLength,
            $this->algorithm,
        ))
            ->atPath('hash')
            ->addViolation();
    }
}
