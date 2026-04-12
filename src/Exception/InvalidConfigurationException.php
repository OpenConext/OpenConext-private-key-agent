<?php

declare(strict_types=1);

namespace App\Exception;

final class InvalidConfigurationException extends BackendException
{
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
