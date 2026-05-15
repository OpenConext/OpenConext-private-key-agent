<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Crypto;

enum EncryptionAlgorithm: string
{
    case RsaPkcs1V15       = 'rsa-pkcs1-v1_5';
    case RsaOaepMgf1Sha1   = 'rsa-pkcs1-oaep-mgf1-sha1';
    case RsaOaepMgf1Sha224 = 'rsa-pkcs1-oaep-mgf1-sha224';
    case RsaOaepMgf1Sha256 = 'rsa-pkcs1-oaep-mgf1-sha256';
    case RsaOaepMgf1Sha384 = 'rsa-pkcs1-oaep-mgf1-sha384';
    case RsaOaepMgf1Sha512 = 'rsa-pkcs1-oaep-mgf1-sha512';
}
