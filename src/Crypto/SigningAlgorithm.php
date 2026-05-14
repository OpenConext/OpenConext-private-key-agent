<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Crypto;

final class SigningAlgorithm
{
    public const string RSA_PKCS1_V1_5_SHA1   = 'rsa-pkcs1-v1_5-sha1';
    public const string RSA_PKCS1_V1_5_SHA256 = 'rsa-pkcs1-v1_5-sha256';
    public const string RSA_PKCS1_V1_5_SHA384 = 'rsa-pkcs1-v1_5-sha384';
    public const string RSA_PKCS1_V1_5_SHA512 = 'rsa-pkcs1-v1_5-sha512';

    public const array ALL = [
        self::RSA_PKCS1_V1_5_SHA1,
        self::RSA_PKCS1_V1_5_SHA256,
        self::RSA_PKCS1_V1_5_SHA384,
        self::RSA_PKCS1_V1_5_SHA512,
    ];

    private function __construct()
    {
    }
}
