<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Service;

use OpenConext\PrivateKeyAgent\Config\AgentConfig;
use OpenConext\PrivateKeyAgent\Config\ClientConfig;
use OpenConext\PrivateKeyAgent\Config\KeyConfig;
use OpenConext\PrivateKeyAgent\Exception\BackendException;
use OpenConext\PrivateKeyAgent\Service\KeyRegistryBootstrapper;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function array_values;
use function file_exists;
use function openssl_pkey_export_to_file;
use function openssl_pkey_new;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_RSA;

class KeyRegistryBootstrapperTest extends TestCase
{
    private static string $keyPath;

    public static function setUpBeforeClass(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair, 'Failed to generate RSA key pair');
        self::$keyPath = tempnam(sys_get_temp_dir(), 'rsa_') . '.pem';
        openssl_pkey_export_to_file($keyPair, self::$keyPath);
    }

    public static function tearDownAfterClass(): void
    {
        if (! file_exists(self::$keyPath)) {
            return;
        }

        unlink(self::$keyPath);
    }

    private function makeConfig(KeyConfig ...$keyConfigs): AgentConfig
    {
        return new AgentConfig(
            agentName: 'test-agent',
            keys: array_values($keyConfigs),
            clients: [new ClientConfig(name: 'client1', token: 'test', allowedKeys: [])],
        );
    }

    public function testCreateRegistryRegistersSigningKey(): void
    {
        $keyConfig   = new KeyConfig(name: 'my-key', keyPath: self::$keyPath, operations: ['sign']);
        $agentConfig = $this->makeConfig($keyConfig);

        $bootstrapper = new KeyRegistryBootstrapper(new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $backend = $registry->getSigningBackend('my-key');
        $this->assertSame('my-key', $backend->getName());
    }

    public function testCreateRegistryRegistersDecryptionKey(): void
    {
        $keyConfig   = new KeyConfig(name: 'decrypt-key', keyPath: self::$keyPath, operations: ['decrypt']);
        $agentConfig = $this->makeConfig($keyConfig);

        $bootstrapper = new KeyRegistryBootstrapper(new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $backend = $registry->getDecryptionBackend('decrypt-key');
        $this->assertSame('decrypt-key', $backend->getName());
    }

    public function testCreateRegistryRegistersBothOperations(): void
    {
        $keyConfig   = new KeyConfig(name: 'dual-key', keyPath: self::$keyPath, operations: ['sign', 'decrypt']);
        $agentConfig = $this->makeConfig($keyConfig);

        $bootstrapper = new KeyRegistryBootstrapper(new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $this->assertSame('dual-key', $registry->getSigningBackend('dual-key')->getName());
        $this->assertSame('dual-key', $registry->getDecryptionBackend('dual-key')->getName());
    }

    public function testCreateRegistryRegistersAllKeys(): void
    {
        $signingKey    = new KeyConfig(name: 'signing-key', keyPath: self::$keyPath, operations: ['sign']);
        $decryptionKey = new KeyConfig(name: 'decryption-key', keyPath: self::$keyPath, operations: ['decrypt']);
        $agentConfig   = $this->makeConfig($signingKey, $decryptionKey);

        $bootstrapper = new KeyRegistryBootstrapper(new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $this->assertCount(2, $registry->getAllBackends());
    }

    public function testCreateRegistryThrowsWhenKeyFileDoesNotExist(): void
    {
        $keyConfig   = new KeyConfig(name: 'missing-key', keyPath: '/nonexistent/key.pem', operations: ['sign']);
        $agentConfig = $this->makeConfig($keyConfig);

        $this->expectException(BackendException::class);
        $this->expectExceptionMessage('Cannot read key file');

        $bootstrapper = new KeyRegistryBootstrapper(new NullLogger());
        $bootstrapper->createRegistry($agentConfig);
    }

    public function testCreateRegistryLogsInfoForEachRegisteredKey(): void
    {
        $keyConfig1  = new KeyConfig(name: 'key-one', keyPath: self::$keyPath, operations: ['sign']);
        $keyConfig2  = new KeyConfig(name: 'key-two', keyPath: self::$keyPath, operations: ['decrypt']);
        $agentConfig = $this->makeConfig($keyConfig1, $keyConfig2);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->exactly(2))
            ->method('info')
            ->with('Registered key', $this->isType('array'));

        $bootstrapper = new KeyRegistryBootstrapper($logger);
        $bootstrapper->createRegistry($agentConfig);
    }
}
