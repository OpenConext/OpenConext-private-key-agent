<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Exception;

use RuntimeException;
use Throwable;

final class AuthenticationException extends RuntimeException
{
    public function __construct(string $message = 'Authentication required', Throwable|null $previous = null)
    {
        parent::__construct($message, previous: $previous);
    }
}
