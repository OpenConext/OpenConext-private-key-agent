<?php

declare(strict_types=1);

namespace App\Controller;

use App\Dto\SignRequest;
use App\Exception\InvalidRequestException;
use App\Security\AccessControlInterface;
use App\Security\AuthenticatorInterface;
use App\Service\KeyRegistryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;

use function base64_decode;
use function base64_encode;
use function is_array;
use function json_decode;

final class SignController
{
    public function __construct(
        private readonly AuthenticatorInterface $authenticator,
        private readonly AccessControlInterface $accessControl,
        private readonly KeyRegistryInterface $keyRegistry,
        private readonly ValidatorInterface $validator,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route('/sign/{keyName}', name: 'sign', methods: ['POST'])]
    public function sign(Request $request, string $keyName): JsonResponse
    {
        $client = $this->authenticator->authenticate($request);

        $this->accessControl->checkAccess($client, $keyName);

        $data = json_decode($request->getContent(), true);
        if (! is_array($data)) {
            throw new InvalidRequestException('Invalid JSON body');
        }

        $signRequest            = new SignRequest();
        $signRequest->algorithm = $data['algorithm'] ?? '';
        $signRequest->hash      = $data['hash'] ?? '';

        $violations = $this->validator->validate($signRequest);
        if ($violations->count() > 0) {
            throw new InvalidRequestException((string) $violations->get(0)->getMessage());
        }

        $backend = $this->keyRegistry->getSigningBackend($keyName);

        $hashBytes = base64_decode($signRequest->hash, true);
        if ($hashBytes === false) {
            throw new InvalidRequestException('Invalid base64-encoded hash');
        }

        $signatureBytes = $backend->sign($hashBytes, $signRequest->algorithm);

        $this->logger->info('Signing request processed', [
            'client' => $client->name,
            'key' => $keyName,
            'algorithm' => $signRequest->algorithm,
            'backend' => $backend->getName(),
        ]);

        return new JsonResponse([
            'signature' => base64_encode($signatureBytes),
        ]);
    }
}
