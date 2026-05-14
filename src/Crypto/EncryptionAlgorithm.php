<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Crypto;

final class EncryptionAlgorithm
{
    public const string RSA_PKCS1_V1_5             = 'rsa-pkcs1-v1_5';
    public const string RSA_PKCS1_OAEP_MGF1_SHA1   = 'rsa-pkcs1-oaep-mgf1-sha1';
    public const string RSA_PKCS1_OAEP_MGF1_SHA224 = 'rsa-pkcs1-oaep-mgf1-sha224';
    public const string RSA_PKCS1_OAEP_MGF1_SHA256 = 'rsa-pkcs1-oaep-mgf1-sha256';
    public const string RSA_PKCS1_OAEP_MGF1_SHA384 = 'rsa-pkcs1-oaep-mgf1-sha384';
    public const string RSA_PKCS1_OAEP_MGF1_SHA512 = 'rsa-pkcs1-oaep-mgf1-sha512';

    public const array ALL = [
        self::RSA_PKCS1_V1_5,
        self::RSA_PKCS1_OAEP_MGF1_SHA1,
        self::RSA_PKCS1_OAEP_MGF1_SHA224,
        self::RSA_PKCS1_OAEP_MGF1_SHA256,
        self::RSA_PKCS1_OAEP_MGF1_SHA384,
        self::RSA_PKCS1_OAEP_MGF1_SHA512,
    ];

    private function __construct()
    {
    }
}
