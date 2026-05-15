<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Controller;

use OpenConext\PrivateKeyAgent\Backend\DecryptionBackendInterface;
use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Controller\DecryptController;
use OpenConext\PrivateKeyAgent\Crypto\EncryptionAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\AccessDeniedException;
use OpenConext\PrivateKeyAgent\Exception\AuthenticationException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Exception\KeyNotFoundException;
use OpenConext\PrivateKeyAgent\Security\AccessControlService;
use OpenConext\PrivateKeyAgent\Security\TokenAuthenticator;
use OpenConext\PrivateKeyAgent\Service\KeyRegistryInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;

use function base64_encode;
use function json_decode;
use function json_encode;
use function random_bytes;

class DecryptControllerTest extends TestCase
{
    private DecryptController $controller;

    /** @var MockObject&KeyRegistryInterface */
    private KeyRegistryInterface $registry;

    protected function setUp(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'test-client', token: 'test-token', allowedKeys: ['my-key']),
            ],
        );

        $this->registry = $this->createMock(KeyRegistryInterface::class);

        $this->controller = new DecryptController(
            authenticator: new TokenAuthenticator($config),
            accessControl: new AccessControlService(),
            keyRegistry: $this->registry,
            logger: new NullLogger(),
        );
    }

    public function testDecryptReturnsBase64Plaintext(): void
    {
        $plaintext       = 'decrypted data';
        $ciphertextBytes = random_bytes(256);
        $backend         = $this->createMock(DecryptionBackendInterface::class);
        $backend->method('decrypt')
            ->with($ciphertextBytes, EncryptionAlgorithm::RsaPkcs1V15)
            ->willReturn($plaintext);
        $backend->method('getName')->willReturn('my-key');
        $this->registry->method('getDecryptionBackend')->with('my-key')->willReturn($backend);

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode($ciphertextBytes),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $response = $this->controller->decrypt($request, 'my-key');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(base64_encode($plaintext), $body['decrypted_data']);
    }

    public function testDecryptThrowsOnMissingAuthorizationHeader(): void
    {
        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(256)),
            ]),
        );
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(AuthenticationException::class);
        $this->controller->decrypt($request, 'my-key');
    }

    public function testDecryptThrowsOnNonArrayJsonBody(): void
    {
        $request = new Request(content: '"just a string"');
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid JSON body');
        $this->controller->decrypt($request, 'my-key');
    }

    public function testDecryptReturns400OnInvalidBody(): void
    {
        $backend = $this->createMock(DecryptionBackendInterface::class);
        $this->registry->method('getDecryptionBackend')->willReturn($backend);

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(64)), // too small (< 128 bytes)
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(InvalidRequestException::class);
        $this->controller->decrypt($request, 'my-key');
    }

    public function testDecryptThrowsOnUnauthorizedKey(): void
    {
        $this->registry->expects($this->never())->method('getDecryptionBackend');

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(256)),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(AccessDeniedException::class);
        $this->controller->decrypt($request, 'other-key');
    }

    public function testDecryptThrowsOnWrongToken(): void
    {
        $this->registry->expects($this->never())->method('getDecryptionBackend');

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(256)),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer wrong-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(AuthenticationException::class);
        $this->controller->decrypt($request, 'my-key');
    }

    public function testDecryptThrowsWhenKeyNotFound(): void
    {
        $this->registry->method('getDecryptionBackend')
            ->with('my-key')
            ->willThrowException(new KeyNotFoundException('Key "my-key" not found or does not permit decryption'));

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(256)),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(KeyNotFoundException::class);
        $this->controller->decrypt($request, 'my-key');
    }
}
