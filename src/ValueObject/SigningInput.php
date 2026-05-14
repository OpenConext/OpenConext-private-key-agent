<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function array_key_exists;
use function base64_decode;
use function in_array;
use function is_string;
use function preg_match;
use function sprintf;
use function strlen;

final readonly class SigningInput
{
    private const array ALGORITHMS = [
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

    private const string BASE64_PATTERN = '/^[A-Za-z0-9+\/]*={0,2}\z/';

    public string $hashBytes;

    private function __construct(public string $algorithm, string $hashBase64)
    {
        if (! in_array($algorithm, self::ALGORITHMS, true)) {
            throw new InvalidRequestException('Invalid signing algorithm.');
        }

        $decoded = self::decodeBase64($hashBase64, 'hash');

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

    private static function decodeBase64(string $value, string $fieldName): string
    {
        if ($value === '') {
            throw new InvalidRequestException(sprintf('The %s field must not be empty.', $fieldName));
        }

        if (preg_match(self::BASE64_PATTERN, $value) !== 1) {
            throw new InvalidRequestException(sprintf('Invalid base64-encoded %s.', $fieldName));
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new InvalidRequestException(sprintf('Invalid base64-encoded %s.', $fieldName));
        }

        return $decoded;
    }
}
