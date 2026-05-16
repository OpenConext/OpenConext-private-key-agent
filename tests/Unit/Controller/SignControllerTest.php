<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Controller;

use OpenConext\PrivateKeyAgent\Backend\SigningBackendInterface;
use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Controller\SignController;
use OpenConext\PrivateKeyAgent\Crypto\SigningAlgorithm;
use OpenConext\PrivateKeyAgent\Exception\AccessDeniedException;
use OpenConext\PrivateKeyAgent\Exception\AuthenticationException;
use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use OpenConext\PrivateKeyAgent\Security\AccessControlService;
use OpenConext\PrivateKeyAgent\Security\TokenAuthenticator;
use OpenConext\PrivateKeyAgent\Service\KeyRegistryInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;

use function base64_encode;
use function hash;
use function json_decode;
use function json_encode;
use function random_bytes;

class SignControllerTest extends TestCase
{
    private SignController $controller;

    /** @var MockObject&KeyRegistryInterface */
    private KeyRegistryInterface $registry;
    private TokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $config = new AgentConfig(
            agentName: 'test-agent',
            keys: [],
            clients: [
                new ClientConfig(name: 'test-client', token: 'test-token', allowedKeys: ['my-key']),
            ],
        );

        $this->authenticator = new TokenAuthenticator($config);
        $this->registry      = $this->createMock(KeyRegistryInterface::class);

        $this->controller = new SignController(
            authenticator: $this->authenticator,
            accessControl: new AccessControlService(),
            keyRegistry: $this->registry,
            logger: new NullLogger(),
        );
    }

    public function testSignReturnsBase64Signature(): void
    {
        $signatureBytes = random_bytes(256);
        $hash           = hash('sha256', 'test', true);
        $backend        = $this->createMock(SigningBackendInterface::class);
        $backend->method('sign')
            ->with($hash, SigningAlgorithm::RsaPkcs1V15Sha256)
            ->willReturn($signatureBytes);
        $backend->method('getName')->willReturn('my-key');
        $this->registry->method('getSigningBackend')->with('my-key')->willReturn($backend);

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5-sha256',
                'hash' => base64_encode($hash),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $response = $this->controller->sign($request, 'my-key');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(base64_encode($signatureBytes), $body['signature']);
    }

    public function testSignThrowsOnInvalidAlgorithm(): void
    {
        $this->registry->expects($this->never())->method('getSigningBackend');

        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'invalid-algo',
                'hash' => base64_encode(random_bytes(32)),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(InvalidRequestException::class);
        $this->controller->sign($request, 'my-key');
    }

    public function testSignThrowsOnMissingToken(): void
    {
        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5-sha256',
                'hash' => base64_encode(random_bytes(32)),
            ]),
        );
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(AuthenticationException::class);
        $this->controller->sign($request, 'my-key');
    }

    public function testSignThrowsOnUnauthorizedKey(): void
    {
        $this->registry->expects($this->never())->method('getSigningBackend');

        $hash    = hash('sha256', 'test', true);
        $request = new Request(
            content: (string) json_encode([
                'algorithm' => 'rsa-pkcs1-v1_5-sha256',
                'hash' => base64_encode($hash),
            ]),
        );
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(AccessDeniedException::class);
        $this->controller->sign($request, 'other-key');
    }

    public function testSignThrowsOnNonArrayJsonBody(): void
    {
        $request = new Request(content: '"just a string"');
        $request->headers->set('Authorization', 'Bearer test-token');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid JSON body');
        $this->controller->sign($request, 'my-key');
    }
}
