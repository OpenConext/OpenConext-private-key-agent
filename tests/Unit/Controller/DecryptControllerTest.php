<?php

declare(strict_types=1);

namespace App\Tests\Unit\Controller;

use App\Backend\DecryptionBackendInterface;
use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Controller\DecryptController;
use App\Exception\AuthenticationException;
use App\Exception\InvalidRequestException;
use App\Security\AccessControlService;
use App\Security\TokenAuthenticator;
use App\Service\KeyRegistryInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Validation;

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
            validator: Validation::createValidatorBuilder()->enableAttributeMapping()->getValidator(),
            logger: new NullLogger(),
        );
    }

    public function testDecryptReturnsBase64Plaintext(): void
    {
        $plaintext = 'decrypted data';
        $backend   = $this->createMock(DecryptionBackendInterface::class);
        $backend->method('decrypt')->willReturn($plaintext);
        $backend->method('getName')->willReturn('my-key');
        $this->registry->method('getDecryptionBackend')->with('my-key')->willReturn($backend);

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5',
                'encrypted_data' => base64_encode(random_bytes(256)),
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
}
