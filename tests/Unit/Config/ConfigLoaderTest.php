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
        $this->assertCount(1, $config->keys);
        $this->assertSame('my-key', $config->keys[0]->name);
        $this->assertSame('/tmp/test-key.pem', $config->keys[0]->keyPath);
        $this->assertSame(['sign', 'decrypt'], $config->keys[0]->operations);
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

    public function testLoadThrowsOnEmptyOperations(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('at least one operation');
        ConfigLoader::load(__DIR__ . '/../../fixtures/invalid-empty-operations.yaml');
    }

    public function testLoadThrowsOnUnknownOperation(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('unknown operation');
        ConfigLoader::load(__DIR__ . '/../../fixtures/invalid-unknown-operation.yaml');
    }

    public function testLoadThrowsOnDuplicateKeyNames(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: dupe
    key_path: /tmp/key.pem
    operations: [sign]
  - name: dupe
    key_path: /tmp/key.pem
    operations: [decrypt]
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

    public function testLoadThrowsOnMissingKeyPath(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('key_path');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnNoClients(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
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
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
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
}
