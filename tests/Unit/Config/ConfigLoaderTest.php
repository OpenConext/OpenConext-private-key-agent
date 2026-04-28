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

    public function testLoadThrowsUnsupportedBackendTypeIsRejected(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
backend_groups:
  - name: backend1
    type: unsupported
    key_path: /var/www/html/config/keys/signing.key
keys:
  - name: k1
    signing_backends: [backend1]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('invalid type');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }
}
