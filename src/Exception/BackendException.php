<?php

declare(strict_types=1);

namespace App\Exception;

use RuntimeException;
use Throwable;

class BackendException extends RuntimeException
{
    public function __construct(string $message = 'Backend error', Throwable|null $previous = null)
    {
        parent::__construct($message, previous: $previous);
    }
}
