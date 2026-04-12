<?php

declare(strict_types=1);

namespace App\Crypto;

use InvalidArgumentException;

use function hex2bin;
use function sprintf;

final class DigestInfoBuilder
{
    /**
     * DER-encoded DigestInfo prefixes per algorithm (RFC 8017, Section 9.2, Note 1).
     * Each prefix is concatenated with the raw hash bytes to produce the DigestInfo
     * structure expected by PKCS#1 v1.5 RSA signing.
     */
    private const array PREFIXES = [
        'rsa-pkcs1-v1_5-sha1'   => '3021300906052b0e03021a05000414',
        'rsa-pkcs1-v1_5-sha256' => '3031300d060960864801650304020105000420',
        'rsa-pkcs1-v1_5-sha384' => '3041300d060960864801650304020205000430',
        'rsa-pkcs1-v1_5-sha512' => '3051300d060960864801650304020305000440',
    ];

    /**
     * Prepends the DER-encoded DigestInfo prefix to the raw hash bytes.
     *
     * @param string $hash      Raw hash bytes
     * @param string $algorithm Algorithm identifier (e.g. 'rsa-pkcs1-v1_5-sha256')
     *
     * @return string DigestInfo || Hash bytes
     *
     * @throws InvalidArgumentException If the algorithm is not supported.
     */
    public static function prepend(string $hash, string $algorithm): string
    {
        if (! isset(self::PREFIXES[$algorithm])) {
            throw new InvalidArgumentException(sprintf('Unsupported algorithm: %s', $algorithm));
        }

        return hex2bin(self::PREFIXES[$algorithm]) . $hash;
    }
}
