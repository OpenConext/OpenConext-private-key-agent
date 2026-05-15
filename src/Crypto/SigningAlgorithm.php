<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Crypto;

enum SigningAlgorithm: string
{
    case RsaPkcs1V15Sha1   = 'rsa-pkcs1-v1_5-sha1';
    case RsaPkcs1V15Sha256 = 'rsa-pkcs1-v1_5-sha256';
    case RsaPkcs1V15Sha384 = 'rsa-pkcs1-v1_5-sha384';
    case RsaPkcs1V15Sha512 = 'rsa-pkcs1-v1_5-sha512';
}
