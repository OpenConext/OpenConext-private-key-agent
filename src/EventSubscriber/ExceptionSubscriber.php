<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Config\AgentConfig;
use App\Exception\AccessDeniedException;
use App\Exception\AuthenticationException;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use App\Exception\KeyNotFoundException;
use App\Exception\RateLimitException;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

use function max;
use function sprintf;
use function str_replace;
use function time;

final class ExceptionSubscriber implements EventSubscriberInterface
{
    private readonly string $realm;

    public function __construct(AgentConfig $config, private readonly LoggerInterface $logger)
    {
        $this->realm = $config->agentName;
    }

    /** @return array<string, array{string, int}> */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::EXCEPTION => ['onKernelException', 0],
        ];
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        [$status, $error, $message] = match (true) {
            $exception instanceof InvalidRequestException      => [400, 'invalid_request', $exception->getMessage()],
            $exception instanceof AuthenticationException      => [401, 'invalid_token', $exception->getMessage()],
            $exception instanceof AccessDeniedException        => [403, 'access_denied', $exception->getMessage()],
            $exception instanceof KeyNotFoundException         => [404, 'not_found', $exception->getMessage()],
            $exception instanceof NotFoundHttpException        => [404, 'not_found', 'Route not found'],
            $exception instanceof MethodNotAllowedHttpException => [405, 'method_not_allowed', 'Method not allowed'],
            $exception instanceof RateLimitException           => [429, 'too_many_requests', $exception->getMessage()],
            $exception instanceof BackendException             => [500, 'server_error', 'A backend operation failed'],
            default                                            => [500, 'server_error', 'Internal server error'],
        };

        if ($exception instanceof AuthenticationException || $exception instanceof AccessDeniedException) {
            $this->logger->warning($exception->getMessage());
        } elseif ($exception instanceof RateLimitException) {
            $this->logger->warning($exception->getMessage());
        } elseif ($exception instanceof BackendException || $status === 500) {
            $this->logger->error($exception->getMessage());
        }

        $response = new JsonResponse([
            'status' => $status,
            'error' => $error,
            'message' => $message,
        ], $status);

        if ($exception instanceof AuthenticationException) {
            $response->headers->set(
                'WWW-Authenticate',
                sprintf(
                    'Bearer realm="%s", error="%s", error_description="%s"',
                    $this->realm,
                    $error,
                    str_replace('"', '\\"', $message),
                ),
            );
        }

        if ($exception instanceof RateLimitException) {
            $retryAfter = max(1, $exception->getRetryAfter()->getTimestamp() - time());
            $response->headers->set('Retry-After', (string) $retryAfter);
        }

        $event->setResponse($response);
    }
}
