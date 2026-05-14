<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function array_key_exists;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;

final readonly class SigningInput
{
    private const array HASH_LENGTHS = [
        SigningAlgorithm::RSA_PKCS1_V1_5_SHA1   => 20,
        SigningAlgorithm::RSA_PKCS1_V1_5_SHA256 => 32,
        SigningAlgorithm::RSA_PKCS1_V1_5_SHA384 => 48,
        SigningAlgorithm::RSA_PKCS1_V1_5_SHA512 => 64,
    ];

    public string $hashBytes;

    private function __construct(public string $algorithm, string $hashBase64)
    {
        if (! in_array($algorithm, SigningAlgorithm::ALL, true)) {
            throw new InvalidRequestException('Invalid signing algorithm.');
        }

        $decoded = Base64Decoder::decode($hashBase64, 'hash');

        $expected = self::HASH_LENGTHS[$algorithm];
        if (strlen($decoded) !== $expected) {
            throw new InvalidRequestException(sprintf(
                'Hash length %d bytes does not match expected %d bytes for %s.',
                strlen($decoded),
                $expected,
                $algorithm,
            ));
        }

        $this->hashBytes = $decoded;
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        if (! array_key_exists('algorithm', $data)) {
            throw new InvalidRequestException('The algorithm field is required.');
        }

        if (! is_string($data['algorithm'])) {
            throw new InvalidRequestException('The algorithm field must be a string.');
        }

        if (! array_key_exists('hash', $data)) {
            throw new InvalidRequestException('The hash field is required.');
        }

        if (! is_string($data['hash'])) {
            throw new InvalidRequestException('The hash field must be a string.');
        }

        return new self($data['algorithm'], $data['hash']);
    }
}
