<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Controller;

use OpenConext\PrivateKeyAgent\Config\KeyName;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Exception\OpenSSLException;
use OpenConext\PrivateKeyAgent\Security\AccessControlInterface;
use OpenConext\PrivateKeyAgent\Security\AuthenticatorInterface;
use OpenConext\PrivateKeyAgent\Service\KeyRegistryInterface;
use OpenConext\PrivateKeyAgent\ValueObject\DecryptionInput;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

use function base64_encode;
use function hrtime;
use function round;

final class DecryptController
{
    use JsonBodyParser;

    public function __construct(
        private readonly AuthenticatorInterface $authenticator,
        private readonly AccessControlInterface $accessControl,
        private readonly KeyRegistryInterface $keyRegistry,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route('/v1/decrypt/{keyName}', name: 'decrypt', methods: ['POST'], requirements: ['keyName' => KeyName::PATTERN])]
    public function decrypt(Request $request, string $keyName): JsonResponse
    {
        $client = $this->authenticator->authenticate($request);

        $this->accessControl->checkAccess($client, $keyName);

        $input = DecryptionInput::fromArray($this->parseJsonBody($request));

        $backend = $this->keyRegistry->getDecryptionBackend($keyName);
        $start   = hrtime(true);

        try {
            $plaintextBytes = $backend->decrypt($input->ciphertextBytes, $input->algorithm);
        } catch (OpenSSLException) {
            $this->logger->warning('Decryption failed (invalid ciphertext)', [
                'client'    => $client->name,
                'key'       => $keyName,
                'algorithm' => $input->algorithm,
            ]);

            throw new InvalidRequestException('Decryption failed');
        }

        $durationMs = (int) round((hrtime(true) - $start) / 1_000_000);

        $this->logger->debug('decrypt completed', [
            'key'        => $keyName,
            'algorithm'  => $input->algorithm,
            'durationMs' => $durationMs,
            'backend'    => $backend->getName(),
        ]);

        $this->logger->info('Decryption request processed', [
            'client'    => $client->name,
            'key'       => $keyName,
            'algorithm' => $input->algorithm,
            'backend'   => $backend->getName(),
        ]);

        return new JsonResponse([
            'decrypted_data' => base64_encode($plaintextBytes),
        ]);
    }
}
