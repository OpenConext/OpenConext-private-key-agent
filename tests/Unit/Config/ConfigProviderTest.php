<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Config;

use OpenConext\PrivateKeyAgent\Config\ConfigProvider;
use OpenConext\PrivateKeyAgent\Exception\InvalidConfigurationException;
use PHPUnit\Framework\TestCase;

class ConfigProviderTest extends TestCase
{
    public function testGetConfigReturnsAgentConfig(): void
    {
        $provider = new ConfigProvider(__DIR__ . '/../../fixtures/valid-config.yaml');
        $config   = $provider->getConfig();

        $this->assertSame('test-agent', $config->agentName);
    }

    public function testGetConfigCachesResult(): void
    {
        $provider = new ConfigProvider(__DIR__ . '/../../fixtures/valid-config.yaml');
        $config1  = $provider->getConfig();
        $config2  = $provider->getConfig();

        $this->assertSame($config1, $config2);
    }

    public function testGetConfigThrowsWithEmptyPath(): void
    {
        $provider = new ConfigProvider('');

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Config path is not set');
        $provider->getConfig();
    }
}
