<?php

declare(strict_types=1);

namespace App\Tests\Unit\Service;

use App\Backend\BackendFactory;
use App\Backend\OpenSslBackendTypeFactory;
use App\Config\AgentConfig;
use App\Config\BackendGroupConfig;
use App\Config\ClientConfig;
use App\Config\KeyConfig;
use App\Service\KeyRegistryBootstrapper;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

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

    public function testCreateRegistryPopulatesSigningBackends(): void
    {
        $backendConfig = new BackendGroupConfig(name: 'soft', type: 'openssl', keyPath: self::$keyPath);
        $keyConfig     = new KeyConfig(name: 'my-key', signingBackends: ['soft']);
        $clientConfig  = new ClientConfig(name: 'client1', token: 'test', allowedKeys: ['my-key']);
        $agentConfig   = new AgentConfig(
            agentName: 'test-agent',
            backends: [$backendConfig],
            keys: [$keyConfig],
            clients: [$clientConfig],
        );

        $bootstrapper = new KeyRegistryBootstrapper(new BackendFactory([new OpenSslBackendTypeFactory()]), new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $this->assertContains('my-key', $registry->getSigningKeyNames());
    }

    public function testCreateRegistryPopulatesDecryptionBackends(): void
    {
        $backendConfig = new BackendGroupConfig(name: 'soft', type: 'openssl', keyPath: self::$keyPath);
        $keyConfig     = new KeyConfig(name: 'decrypt-key', decryptionBackends: ['soft']);
        $clientConfig  = new ClientConfig(name: 'client1', token: 'test', allowedKeys: ['decrypt-key']);
        $agentConfig   = new AgentConfig(
            agentName: 'test-agent',
            backends: [$backendConfig],
            keys: [$keyConfig],
            clients: [$clientConfig],
        );

        $bootstrapper = new KeyRegistryBootstrapper(new BackendFactory([new OpenSslBackendTypeFactory()]), new NullLogger());
        $registry     = $bootstrapper->createRegistry($agentConfig);

        $this->assertContains('decrypt-key', $registry->getDecryptionKeyNames());
    }
}
