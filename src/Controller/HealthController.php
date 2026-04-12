<?php

declare(strict_types=1);

namespace App\Controller;

use App\Service\KeyRegistryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

use function array_unique;
use function array_values;
use function count;

final class HealthController
{
    public function __construct(
        private readonly KeyRegistryInterface $keyRegistry,
    ) {
    }

    #[Route('/health', name: 'health', methods: ['GET'])]
    public function health(): JsonResponse
    {
        $unhealthyNames = [];
        foreach ($this->keyRegistry->getAllBackends() as $backend) {
            if ($backend->isHealthy()) {
                continue;
            }

            $unhealthyNames[] = $backend->getName();
        }

        if (count($unhealthyNames) > 0) {
            return new JsonResponse([
                'status'             => 503,
                'error'              => 'server_error',
                'message'            => 'One or more backends are unhealthy',
                'unhealthy_backends' => array_values(array_unique($unhealthyNames)),
            ], 503);
        }

        return new JsonResponse(['status' => 'OK']);
    }

    #[Route('/health/backend/{backendName}', name: 'health_backend', methods: ['GET'])]
    public function backendHealth(string $backendName): JsonResponse
    {
        $backends = $this->keyRegistry->getBackendsByName($backendName);

        if (count($backends) === 0) {
            return new JsonResponse([
                'status'       => 'not_found',
                'backend_name' => $backendName,
            ], 404);
        }

        foreach ($backends as $backend) {
            if (! $backend->isHealthy()) {
                return new JsonResponse([
                    'status'       => 503,
                    'error'        => 'server_error',
                    'message'      => 'Backend is unhealthy',
                    'backend_name' => $backendName,
                ], 503);
            }
        }

        return new JsonResponse([
            'status'       => 'OK',
            'backend_name' => $backendName,
        ]);
    }
}
