<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Exception;

use function implode;
use function openssl_error_string;

final class OpenSSLException extends BackendException
{
    public function __construct(string $message)
    {
        $errors = [];
        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        $detail = $errors !== [] ? implode('; ', $errors) : 'unknown OpenSSL error';

        parent::__construct($message . ': ' . $detail);
    }
}
