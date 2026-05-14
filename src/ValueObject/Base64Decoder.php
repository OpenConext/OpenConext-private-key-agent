<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\ValueObject;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;

use function base64_decode;
use function preg_match;
use function sprintf;

final class Base64Decoder
{
    private const string BASE64_PATTERN = '/^[A-Za-z0-9+\/]*={0,2}\z/';

    public static function decode(string $value, string $fieldName): string
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
