<?php

declare(strict_types=1);

namespace App\Tests\Unit\Controller;

use App\Backend\SigningBackendInterface;
use App\Config\AgentConfig;
use App\Config\ClientConfig;
use App\Controller\SignController;
use App\Exception\AccessDeniedException;
use App\Exception\AuthenticationException;
use App\Exception\InvalidRequestException;
use App\Exception\KeyNotFoundException;
use App\Security\AccessControlService;
use App\Security\TokenAuthenticator;
use App\Service\KeyRegistryInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\LimiterInterface;
use Symfony\Component\RateLimiter\RateLimit;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Validator\Validation;

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

        $this->authenticator = new TokenAuthenticator($config, $this->makeAcceptingLimiter());
        $this->registry      = $this->createMock(KeyRegistryInterface::class);

        $this->controller = new SignController(
            authenticator: $this->authenticator,
            accessControl: new AccessControlService(),
            keyRegistry: $this->registry,
            validator: Validation::createValidatorBuilder()->enableAttributeMapping()->getValidator(),
            logger: new NullLogger(),
        );
    }

    private function makeAcceptingLimiter(): RateLimiterFactoryInterface
    {
        $rateLimit = $this->createMock(RateLimit::class);
        $rateLimit->method('isAccepted')->willReturn(true);

        $limiter = $this->createMock(LimiterInterface::class);
        $limiter->method('consume')->willReturn($rateLimit);

        $factory = $this->createMock(RateLimiterFactoryInterface::class);
        $factory->method('create')->willReturn($limiter);

        return $factory;
    }

    public function testSignReturnsBase64Signature(): void
    {
        $signatureBytes = random_bytes(256);
        $backend        = $this->createMock(SigningBackendInterface::class);
        $backend->method('sign')->willReturn($signatureBytes);
        $backend->method('getName')->willReturn('my-key');
        $this->registry->method('getSigningBackend')->with('my-key')->willReturn($backend);

        $hash    = hash('sha256', 'test', true);
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

    public function testSignReturns400OnInvalidAlgorithm(): void
    {
        $backend = $this->createMock(SigningBackendInterface::class);
        $this->registry->method('getSigningBackend')->willReturn($backend);

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

    public function testSignReturns401OnMissingToken(): void
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

    public function testSignReturns403OnUnauthorizedKey(): void
    {
        $this->registry->method('getSigningBackend')
            ->with('other-key')
            ->willThrowException(new KeyNotFoundException('Key "other-key" not found or does not permit signing'));

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
