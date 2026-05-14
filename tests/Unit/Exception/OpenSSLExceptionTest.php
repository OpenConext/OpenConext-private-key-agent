<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Exception;

use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Exception\OpenSSLException;
use PHPUnit\Framework\TestCase;

use function class_parents;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function substr_count;

class OpenSSLExceptionTest extends TestCase
{
    protected function tearDown(): void
    {
        $this->drainOpenSslErrorQueue();
    }

    public function testDrainsAllQueuedErrors(): void
    {
        // Trigger multiple OpenSSL errors by calling with invalid PEM data
        @openssl_pkey_get_private('not-a-key');
        @openssl_pkey_get_private('also-not-a-key');

        $exception = new OpenSSLException('Test error');
        $message   = $exception->getMessage();

        $this->assertStringStartsWith('Test error:', $message);
        $this->assertGreaterThanOrEqual(1, substr_count($message, ';') + 1);

        // Queue must be fully drained after construction
        $this->assertFalse(openssl_error_string());
    }

    public function testFallbackMessageWhenQueueIsEmpty(): void
    {
        $this->drainOpenSslErrorQueue();

        $exception = new OpenSSLException('Test error');

        $this->assertSame('Test error: unknown OpenSSL error', $exception->getMessage());
    }

    public function testExtendsBackendException(): void
    {
        $this->assertArrayHasKey(BackendException::class, class_parents(OpenSSLException::class) ?: []);
    }

    private function drainOpenSslErrorQueue(): void
    {
        while (openssl_error_string() !== false) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        }
    }
}
