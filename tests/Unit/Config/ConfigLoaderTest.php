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

    public function testLoadThrowsOnNonArrayKeys(): void
    {
        $yaml    = "agent_name: test-agent\nkeys: bad-string\nclients:\n  - name: c1\n    token: test-token-value-at-least-32-chars-long\n    allowed_keys: []\n";
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('"keys"');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnScalarKeyEntry(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - bad-scalar-entry
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: []
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('"keys"');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnScalarClientEntry(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - bad-scalar-entry
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('"clients"');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnMissingKeyName(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: []
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('Key must have a name');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnMissingClientName(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('Client must have a name');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnMissingClientToken(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('token');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnMissingKeys(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('At least one key must be configured');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnEmptyKeys(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys: []
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('At least one key must be configured');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnInvalidKeyName(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: "invalid key!"
    key_path: /tmp/key.pem
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
            $this->expectExceptionMessage('[a-zA-Z0-9_-]{1,64}');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnDuplicateClientNames(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: sp
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
  - name: sp
    token: another-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('Duplicate client name');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnEmptyAllowedKeys(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: []
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('allowed_keys must be a non-empty list');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnMissingAllowedKeys(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('allowed_keys must be a non-empty list');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadThrowsOnNonStringAllowedKeyEntry(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [123]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->expectExceptionMessage('allowed_keys entries must be non-empty strings');
            ConfigLoader::load($tmpFile);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testLoadValidConfigWithWildcardAllowedKeys(): void
    {
        $yaml    = <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: ["*"]
YAML;
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $config = ConfigLoader::load($tmpFile);
            $this->assertSame(['*'], $config->clients[0]->allowedKeys);
        } finally {
            unlink($tmpFile);
        }
    }
}
