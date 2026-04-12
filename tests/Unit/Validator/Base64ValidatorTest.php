<?php

declare(strict_types=1);

namespace App\Tests\Unit\Validator;

use App\Validator\Base64;
use App\Validator\Base64Validator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Context\ExecutionContextInterface;
use Symfony\Component\Validator\Violation\ConstraintViolationBuilderInterface;

use function base64_encode;

class Base64ValidatorTest extends TestCase
{
    private Base64Validator $validator;
    private ExecutionContextInterface&MockObject $context;

    protected function setUp(): void
    {
        $this->validator = new Base64Validator();
        $this->context   = $this->createMock(ExecutionContextInterface::class);
        $this->validator->initialize($this->context);
    }

    public function testValidBase64Passes(): void
    {
        $this->context->expects($this->never())->method('buildViolation');
        $this->validator->validate(base64_encode('hello world'), new Base64());
    }

    public function testValidBase64WithPaddingPasses(): void
    {
        $this->context->expects($this->never())->method('buildViolation');
        // "a" encodes to "YQ==" (with padding)
        $this->validator->validate('YQ==', new Base64());
    }

    public function testEmptyStringPasses(): void
    {
        // Empty or null values are typically handled by NotBlank, not this validator
        $this->context->expects($this->never())->method('buildViolation');
        $this->validator->validate('', new Base64());
    }

    public function testNullPasses(): void
    {
        $this->context->expects($this->never())->method('buildViolation');
        $this->validator->validate(null, new Base64());
    }

    public function testInvalidBase64Fails(): void
    {
        $builder = $this->createMock(ConstraintViolationBuilderInterface::class);
        $builder->method('setParameter')->willReturn($builder);
        $builder->expects($this->once())->method('addViolation');

        $this->context->expects($this->once())->method('buildViolation')->willReturn($builder);

        $this->validator->validate('not!valid!base64!!!', new Base64());
    }

    public function testBase64WithWhitespaceFails(): void
    {
        $builder = $this->createMock(ConstraintViolationBuilderInterface::class);
        $builder->method('setParameter')->willReturn($builder);
        $builder->expects($this->once())->method('addViolation');

        $this->context->expects($this->once())->method('buildViolation')->willReturn($builder);

        $this->validator->validate("YQ==\n", new Base64());
    }
}
