<?php

declare(strict_types=1);

namespace App\Controller;

use App\Config\KeyName;
use App\Service\KeyRegistryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

use function array_unique;
use function array_values;
use function count;
use function sprintf;

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
                'status'          => 503,
                'error'           => 'server_error',
                'message'         => 'One or more keys are unhealthy',
                'unhealthy_keys'  => array_values(array_unique($unhealthyNames)),
            ], 503);
        }

        return new JsonResponse(['status' => 'OK']);
    }

    #[Route('/health/key/{keyName}', name: 'health_key', methods: ['GET'], requirements: ['keyName' => KeyName::PATTERN])]
    public function keyHealth(string $keyName): JsonResponse
    {
        $backend = $this->keyRegistry->findBackend($keyName);

        if ($backend === null) {
            return new JsonResponse([
                'status'  => 404,
                'error'   => 'not_found',
                'message' => sprintf('Key "%s" not found', $keyName),
            ], 404);
        }

        if (! $backend->isHealthy()) {
            return new JsonResponse([
                'status'   => 503,
                'error'    => 'server_error',
                'message'  => 'Key is unhealthy',
                'key_name' => $keyName,
            ], 503);
        }

        return new JsonResponse([
            'status'   => 'OK',
            'key_name' => $keyName,
        ]);
    }
}
