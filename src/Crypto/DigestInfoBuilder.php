<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Crypto;

use function hex2bin;

final class DigestInfoBuilder
{
    /**
     * Prepends the DER-encoded DigestInfo prefix to the raw hash bytes.
     * Prefixes per RFC 8017, Section 9.2, Note 1.
     *
     * @param string           $hash      Raw hash bytes
     * @param SigningAlgorithm $algorithm Signing algorithm
     *
     * @return string DigestInfo structure (prefix || hash bytes)
     */
    public static function prepend(string $hash, SigningAlgorithm $algorithm): string
    {
        $prefix = match ($algorithm) {
            SigningAlgorithm::RsaPkcs1V15Sha1   => '3021300906052b0e03021a05000414',
            SigningAlgorithm::RsaPkcs1V15Sha256 => '3031300d060960864801650304020105000420',
            SigningAlgorithm::RsaPkcs1V15Sha384 => '3041300d060960864801650304020205000430',
            SigningAlgorithm::RsaPkcs1V15Sha512 => '3051300d060960864801650304020305000440',
        };

        return hex2bin($prefix) . $hash;
    }
}
