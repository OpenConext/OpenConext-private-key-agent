<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Controller;

use OpenConext\PrivateKeyAgent\Config\KeyName;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Security\AccessControlInterface;
use OpenConext\PrivateKeyAgent\Security\AuthenticatorInterface;
use OpenConext\PrivateKeyAgent\Service\KeyRegistryInterface;
use OpenConext\PrivateKeyAgent\ValueObject\SigningInput;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

use function base64_encode;
use function hrtime;
use function is_array;
use function json_decode;
use function round;

final class SignController
{
    public function __construct(
        private readonly AuthenticatorInterface $authenticator,
        private readonly AccessControlInterface $accessControl,
        private readonly KeyRegistryInterface $keyRegistry,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route('/v1/sign/{keyName}', name: 'sign', methods: ['POST'], requirements: ['keyName' => KeyName::PATTERN])]
    public function sign(Request $request, string $keyName): JsonResponse
    {
        $client = $this->authenticator->authenticate($request);

        $this->accessControl->checkAccess($client, $keyName);

        $data = json_decode($request->getContent(), true);
        if (! is_array($data)) {
            throw new InvalidRequestException('Invalid JSON body');
        }

        $input = SigningInput::fromArray($data);

        $backend        = $this->keyRegistry->getSigningBackend($keyName);
        $start          = hrtime(true);
        $signatureBytes = $backend->sign($input->hashBytes, $input->algorithm);
        $durationMs     = (int) round((hrtime(true) - $start) / 1_000_000);

        $this->logger->debug('sign completed', [
            'key'        => $keyName,
            'algorithm'  => $input->algorithm,
            'durationMs' => $durationMs,
            'backend'    => $backend->getName(),
        ]);

        $this->logger->info('Signing request processed', [
            'client'    => $client->name,
            'key'       => $keyName,
            'algorithm' => $input->algorithm,
            'backend'   => $backend->getName(),
        ]);

        return new JsonResponse([
            'signature' => base64_encode($signatureBytes),
        ]);
    }
}
