<?php

declare(strict_types=1);

namespace App\Tests\Unit\Config;

use App\Config\ConfigLoader;
use App\Exception\InvalidConfigurationException;
use PHPUnit\Framework\TestCase;

use function file_put_contents;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

class ConfigLoaderTest extends TestCase
{
    public function testLoadValidConfig(): void
    {
        $config = ConfigLoader::load(__DIR__ . '/../../fixtures/valid-config.yaml');

        $this->assertSame('test-agent', $config->agentName);
        $this->assertCount(1, $config->backends);
        $this->assertSame('soft-key-1', $config->backends[0]->name);
        $this->assertSame('openssl', $config->backends[0]->type);
        $this->assertSame('/tmp/test-key.pem', $config->backends[0]->keyPath);
        $this->assertCount(1, $config->keys);
        $this->assertSame('my-key', $config->keys[0]->name);
        $this->assertSame(['soft-key-1'], $config->keys[0]->signingBackends);
        $this->assertSame(['soft-key-1'], $config->keys[0]->decryptionBackends);
        $this->assertCount(1, $config->clients);
        $this->assertSame('test-client', $config->clients[0]->name);
        $this->assertSame(['my-key'], $config->clients[0]->allowedKeys);
    }

    public function testLoadThrowsOnMissingFile(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Config file not found');
        ConfigLoader::load('/nonexistent/path.yaml');
    }

    public function testLoadThrowsOnMissingAgentName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('agent_name');
        ConfigLoader::load(__DIR__ . '/../../fixtures/invalid-missing-agent-name.yaml');
    }

    public function testLoadThrowsOnOrphanBackend(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('orphan-backend');
        ConfigLoader::load(__DIR__ . '/../../fixtures/invalid-orphan-backend.yaml');
    }

    public function testLoadThrowsOnDuplicateKeyNames(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: b1
    type: openssl
    key_path: /tmp/key.pem
keys:
  - name: dupe
    signing_backends: [b1]
  - name: dupe
    signing_backends: [b1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [dupe]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('Duplicate key name');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnUnknownBackendReference(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: b1
    type: openssl
    key_path: /tmp/key.pem
keys:
  - name: k1
    signing_backends: [nonexistent]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('nonexistent');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnNoClients(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: b1
    type: openssl
    key_path: /tmp/key.pem
keys:
  - name: k1
    signing_backends: [b1]
clients: []
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('At least one client');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnEmptyClientToken(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: b1
    type: openssl
    key_path: /tmp/key.pem
keys:
  - name: k1
    signing_backends: [b1]
clients:
  - name: c1
    token: ""
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('non-empty');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadPkcs11Backend(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: hsm1
    type: pkcs11
    pkcs11_lib: /usr/lib/softhsm/libsofthsm2.so
    pkcs11_slot: 0
    pkcs11_pin: "1234"
    pkcs11_key_label: my-key
keys:
  - name: k1
    signing_backends: [hsm1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $config = ConfigLoader::load($tmpFile);
            $this->assertSame('pkcs11', $config->backends[0]->type);
            $this->assertSame('/usr/lib/softhsm/libsofthsm2.so', $config->backends[0]->pkcs11Lib);
            $this->assertSame(0, $config->backends[0]->pkcs11Slot);
            $this->assertSame('1234', $config->backends[0]->pkcs11Pin);
            $this->assertSame('my-key', $config->backends[0]->pkcs11KeyLabel);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadPkcs11BackendWithoutPin(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: hsm1
    type: pkcs11
    pkcs11_lib: /usr/lib/softhsm/libsofthsm2.so
    pkcs11_slot: 0
    pkcs11_key_label: my-key
keys:
  - name: k1
    signing_backends: [hsm1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $config = ConfigLoader::load($tmpFile);
            $this->assertNull($config->backends[0]->pkcs11Pin);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnPkcs11MissingLib(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: hsm1
    type: pkcs11
    pkcs11_slot: 0
    pkcs11_pin: "1234"
    pkcs11_key_label: my-key
keys:
  - name: k1
    signing_backends: [hsm1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [c1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('pkcs11_lib');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadBackendWithEnvironment(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: hsm1
    type: pkcs11
    pkcs11_lib: /usr/lib/softhsm/libsofthsm2.so
    pkcs11_slot: 0
    pkcs11_pin: "1234"
    pkcs11_key_label: my-key
    environment:
      SOFTHSM2_CONF: /etc/softhsm2.conf
      ANOTHER_VAR: "some value"
keys:
  - name: k1
    signing_backends: [hsm1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $config = ConfigLoader::load($tmpFile);
            $this->assertSame(
                ['SOFTHSM2_CONF' => '/etc/softhsm2.conf', 'ANOTHER_VAR' => 'some value'],
                $config->backends[0]->environment,
            );
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadBackendWithoutEnvironmentDefaultsToEmptyArray(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: b1
    type: openssl
    key_path: /tmp/key.pem
keys:
  - name: k1
    signing_backends: [b1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $config = ConfigLoader::load($tmpFile);
            $this->assertSame([], $config->backends[0]->environment);
        } finally {
            unlink($tmpFile);
        }
    }
}
