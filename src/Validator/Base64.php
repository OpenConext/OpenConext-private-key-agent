<?php

declare(strict_types=1);

namespace App\Validator;

use Attribute;
use Symfony\Component\Validator\Constraint;

#[Attribute(Attribute::TARGET_PROPERTY | Attribute::TARGET_METHOD)]
class Base64 extends Constraint
{
    public string $message = 'The value "{{ value }}" is not valid base64.';
}
