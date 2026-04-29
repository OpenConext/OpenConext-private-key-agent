<?php

declare(strict_types=1);

namespace App\Tests\Unit\EventSubscriber;

use App\Config\AgentConfig;
use App\EventSubscriber\ExceptionSubscriber;
use App\Exception\AccessDeniedException;
use App\Exception\AuthenticationException;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

use function json_decode;

class ExceptionSubscriberTest extends TestCase
{
    private ExceptionSubscriber $subscriber;
    private HttpKernelInterface $kernel;

    protected function setUp(): void
    {
        $config           = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [],
        );
        $this->subscriber = new ExceptionSubscriber($config);
        $this->kernel     = $this->createMock(HttpKernelInterface::class);
    }

    public function testInvalidRequestExceptionReturns400(): void
    {
        $event = new ExceptionEvent(
            $this->kernel,
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new InvalidRequestException('Bad field'),
        );

        $this->subscriber->onKernelException($event);
        $response = $event->getResponse();

        $this->assertNotNull($response);
        $this->assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(400, $body['status']);
        $this->assertSame('invalid_request', $body['error']);
        $this->assertSame('Bad field', $body['message']);
    }

    public function testAuthenticationExceptionReturns401WithHeader(): void
    {
        $event = new ExceptionEvent(
            $this->kernel,
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new AuthenticationException('No token'),
        );

        $this->subscriber->onKernelException($event);
        $response = $event->getResponse();

        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('invalid_token', $body['error']);
        $this->assertSame('Bearer realm="test-agent", error="invalid_token", error_description="No token"', $response->headers->get('WWW-Authenticate'));
    }

    public function testAccessDeniedExceptionReturns403(): void
    {
        $event = new ExceptionEvent(
            $this->kernel,
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new AccessDeniedException('Not allowed'),
        );

        $this->subscriber->onKernelException($event);
        $response = $event->getResponse();

        $this->assertNotNull($response);
        $this->assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('access_denied', $body['error']);
    }

    public function testBackendExceptionReturns500(): void
    {
        $event = new ExceptionEvent(
            $this->kernel,
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new BackendException('Backend unreachable'),
        );

        $this->subscriber->onKernelException($event);
        $response = $event->getResponse();

        $this->assertNotNull($response);
        $this->assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('server_error', $body['error']);
        $this->assertSame('A backend operation failed', $body['message']);
        $this->assertNotSame('Backend unreachable', $body['message']);
    }

    public function testGenericExceptionReturns500(): void
    {
        $event = new ExceptionEvent(
            $this->kernel,
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new RuntimeException('Something unexpected'),
        );

        $this->subscriber->onKernelException($event);
        $response = $event->getResponse();

        $this->assertNotNull($response);
        $this->assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame('server_error', $body['error']);
        $this->assertSame('Internal server error', $body['message']);
    }
}
