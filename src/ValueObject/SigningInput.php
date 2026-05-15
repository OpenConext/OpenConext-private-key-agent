<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function array_key_exists;
use function is_string;
use function sprintf;
use function strlen;

final readonly class SigningInput
{
    public string $hashBytes;

    private function __construct(public SigningAlgorithm $algorithm, string $hashBase64)
    {
        $decoded = Base64Decoder::decode($hashBase64, 'hash');

        $expected = self::expectedHashLength($algorithm);
        if (strlen($decoded) !== $expected) {
            throw new InvalidRequestException(sprintf(
                'Hash length %d bytes does not match expected %d bytes for %s.',
                strlen($decoded),
                $expected,
                $algorithm->value,
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

        $algorithm = SigningAlgorithm::tryFrom($data['algorithm'])
            ?? throw new InvalidRequestException('Invalid signing algorithm.');

        return new self($algorithm, $data['hash']);
    }

    private static function expectedHashLength(SigningAlgorithm $algorithm): int
    {
        return match ($algorithm) {
            SigningAlgorithm::RsaPkcs1V15Sha1   => 20,
            SigningAlgorithm::RsaPkcs1V15Sha256 => 32,
            SigningAlgorithm::RsaPkcs1V15Sha384 => 48,
            SigningAlgorithm::RsaPkcs1V15Sha512 => 64,
        };
    }
}
