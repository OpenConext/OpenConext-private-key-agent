<?php

declare(strict_types=1);

namespace App\Exception;

use DateTimeImmutable;
use RuntimeException;
use Throwable;

class RateLimitException extends RuntimeException
{
    public function __construct(
        private readonly DateTimeImmutable $retryAfter,
        string $message = 'Too many failed authentication attempts',
        Throwable|null $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }

    public function getRetryAfter(): DateTimeImmutable
    {
        return $this->retryAfter;
    }
}
