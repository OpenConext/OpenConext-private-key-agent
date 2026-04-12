<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

use function base64_decode;
use function preg_match;

class Base64Validator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (! $constraint instanceof Base64) {
            throw new UnexpectedTypeException($constraint, Base64::class);
        }

        if ($value === null || $value === '') {
            return;
        }

        // Strict base64: only [A-Za-z0-9+/] with optional = padding, no whitespace.
        // Use \z (absolute end-of-string) not $ (which allows trailing newline in PCRE).
        if (preg_match('/^[A-Za-z0-9+\/]*={0,2}\z/', $value) === 1 && base64_decode($value, true) !== false) {
            return;
        }

        $this->context->buildViolation($constraint->message)
            ->setParameter('{{ value }}', $this->formatValue($value))
            ->addViolation();
    }
}
