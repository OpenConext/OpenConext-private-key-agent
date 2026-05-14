<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function array_key_exists;
use function base64_decode;
use function in_array;
use function is_string;
use function preg_match;
use function sprintf;
use function strlen;

final readonly class DecryptionInput
{
    private const int MIN_CIPHERTEXT_BYTES = 128;
    private const int MAX_CIPHERTEXT_BYTES = 1024;

    private const string BASE64_PATTERN = '/^[A-Za-z0-9+\/]*={0,2}\z/';

    public string $ciphertextBytes;

    private function __construct(public string $algorithm, string $encryptedDataBase64)
    {
        if (! in_array($algorithm, EncryptionAlgorithm::ALL, true)) {
            throw new InvalidRequestException('Invalid decryption algorithm.');
        }

        $decoded = self::decodeBase64($encryptedDataBase64, 'encrypted_data');

        $len = strlen($decoded);
        if ($len < self::MIN_CIPHERTEXT_BYTES || $len > self::MAX_CIPHERTEXT_BYTES) {
            throw new InvalidRequestException(sprintf(
                'Encrypted data must be %d-%d bytes, got %d bytes.',
                self::MIN_CIPHERTEXT_BYTES,
                self::MAX_CIPHERTEXT_BYTES,
                $len,
            ));
        }

        $this->ciphertextBytes = $decoded;
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

        if (! array_key_exists('encrypted_data', $data)) {
            throw new InvalidRequestException('The encrypted_data field is required.');
        }

        if (! is_string($data['encrypted_data'])) {
            throw new InvalidRequestException('The encrypted_data field must be a string.');
        }

        return new self($data['algorithm'], $data['encrypted_data']);
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
