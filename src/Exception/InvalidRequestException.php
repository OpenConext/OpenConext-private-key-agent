<?php

declare(strict_types=1);

namespace App\Exception;

use RuntimeException;
use Throwable;

class InvalidRequestException extends RuntimeException
{
    public function __construct(string $message = 'Invalid request', Throwable|null $previous = null)
    {
        parent::__construct($message, previous: $previous);
    }
}
