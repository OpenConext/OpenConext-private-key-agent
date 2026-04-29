<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Config\AgentConfig;
use App\Exception\AccessDeniedException;
use App\Exception\AuthenticationException;
use App\Exception\BackendException;
use App\Exception\InvalidRequestException;
use App\Exception\KeyNotFoundException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

use function sprintf;
use function str_replace;

final class ExceptionSubscriber implements EventSubscriberInterface
{
    private readonly string $realm;

    public function __construct(AgentConfig $config)
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
            $exception instanceof InvalidRequestException => [400, 'invalid_request', $exception->getMessage()],
            $exception instanceof AuthenticationException => [401, 'invalid_token', $exception->getMessage()],
            $exception instanceof AccessDeniedException   => [403, 'access_denied', $exception->getMessage()],
            $exception instanceof KeyNotFoundException    => [404, 'not_found', $exception->getMessage()],
            $exception instanceof BackendException        => [500, 'server_error', 'A backend operation failed'],
            default                                       => [500, 'server_error', 'Internal server error'],
        };

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

        $event->setResponse($response);
    }
}
