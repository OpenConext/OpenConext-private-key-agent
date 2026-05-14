<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function array_key_exists;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;

final readonly class DecryptionInput
{
    private const int MIN_CIPHERTEXT_BYTES = 128;
    private const int MAX_CIPHERTEXT_BYTES = 1024;

    public string $ciphertextBytes;

    private function __construct(public string $algorithm, string $encryptedDataBase64)
    {
        if (! in_array($algorithm, EncryptionAlgorithm::ALL, true)) {
            throw new InvalidRequestException('Invalid decryption algorithm.');
        }

        $decoded = Base64Decoder::decode($encryptedDataBase64, 'encrypted_data');

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
}
