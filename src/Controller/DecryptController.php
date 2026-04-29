<?php

declare(strict_types=1);

namespace App\Controller;

use App\Dto\DecryptRequest;
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
use function hrtime;
use function is_array;
use function json_decode;
use function round;

final class DecryptController
{
    public function __construct(
        private readonly AuthenticatorInterface $authenticator,
        private readonly AccessControlInterface $accessControl,
        private readonly KeyRegistryInterface $keyRegistry,
        private readonly ValidatorInterface $validator,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route('/decrypt/{keyName}', name: 'decrypt', methods: ['POST'])]
    public function decrypt(Request $request, string $keyName): JsonResponse
    {
        $client = $this->authenticator->authenticate($request);

        $this->accessControl->checkAccess($client, $keyName);

        $data = json_decode($request->getContent(), true);
        if (! is_array($data)) {
            throw new InvalidRequestException('Invalid JSON body');
        }

        $decryptRequest                = new DecryptRequest();
        $decryptRequest->algorithm     = $data['algorithm'] ?? '';
        $decryptRequest->encryptedData = $data['encrypted_data'] ?? '';

        $violations = $this->validator->validate($decryptRequest);
        if ($violations->count() > 0) {
            throw new InvalidRequestException((string) $violations->get(0)->getMessage());
        }

        $backend = $this->keyRegistry->getDecryptionBackend($keyName);

        $ciphertextBytes = base64_decode($decryptRequest->encryptedData, true);
        if ($ciphertextBytes === false) {
            throw new InvalidRequestException('Invalid base64-encoded encrypted_data');
        }

        $start          = hrtime(true);
        $plaintextBytes = $backend->decrypt($ciphertextBytes, $decryptRequest->algorithm);
        $durationMs     = (int) round((hrtime(true) - $start) / 1_000_000);

        $this->logger->debug('decrypt completed', [
            'key'        => $keyName,
            'algorithm'  => $decryptRequest->algorithm,
            'durationMs' => $durationMs,
            'backend'    => $backend->getName(),
        ]);

        $this->logger->info('Decryption request processed', [
            'client' => $client->name,
            'key' => $keyName,
            'algorithm' => $decryptRequest->algorithm,
            'backend' => $backend->getName(),
        ]);

        return new JsonResponse([
            'decrypted_data' => base64_encode($plaintextBytes),
        ]);
    }
}
