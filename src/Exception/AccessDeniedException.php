<?php

declare(strict_types=1);

namespace App\Exception;

use RuntimeException;
use Throwable;

class AccessDeniedException extends RuntimeException
{
    public function __construct(string $message = 'Access denied', Throwable|null $previous = null)
    {
        parent::__construct($message, previous: $previous);
    }
}
