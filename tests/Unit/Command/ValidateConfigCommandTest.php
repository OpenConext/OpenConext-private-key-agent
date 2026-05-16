<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Command;

use OpenConext\PrivateKeyAgent\Command\ValidateConfigCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

use function file_exists;
use function file_put_contents;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function sprintf;
use function strtolower;
use function uniqid;
use function unlink;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

class ValidateConfigCommandTest extends TestCase
{
    public function testValidConfigReturnsSuccess(): void
    {
        $tmpFile = $this->createConfigFile(<<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: /tmp/key.pem
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML);

        try {
            $tester = $this->createCommandTester();
            $tester->execute(['config-path' => $tmpFile]);

            $this->assertSame(0, $tester->getStatusCode());
            $this->assertStringContainsString('valid', strtolower($tester->getDisplay()));
        } finally {
            $this->deleteScratchFile($tmpFile);
        }
    }

    public function testInvalidConfigReturnsFailure(): void
    {
        $tmpFile = $this->createConfigFile("invalid: true\n");

        try {
            $tester = $this->createCommandTester();
            $tester->execute(['config-path' => $tmpFile]);

            $this->assertSame(1, $tester->getStatusCode());
            $this->assertStringContainsString('error', strtolower($tester->getDisplay()));
        } finally {
            $this->deleteScratchFile($tmpFile);
        }
    }

    public function testMissingFileReturnsFailure(): void
    {
        $tester = $this->createCommandTester();
        $tester->execute(['config-path' => '/nonexistent/path.yaml']);

        $this->assertSame(1, $tester->getStatusCode());
    }

    public function testCheckKeysReturnsSuccessForValidRsaPrivateKey(): void
    {
        $keyFile    = $this->createPrivateKeyFile(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $configFile = $this->createConfigForKeyPath($keyFile);

        try {
            $tester = $this->createCommandTester();
            $tester->execute([
                'config-path' => $configFile,
                '--check-keys' => true,
            ]);

            $this->assertSame(0, $tester->getStatusCode());
            $this->assertStringContainsString('validated successfully', strtolower($tester->getDisplay()));
        } finally {
            $this->deleteScratchFile($configFile);
            $this->deleteScratchFile($keyFile);
        }
    }

    public function testCheckKeysReturnsFailureForMissingKeyFile(): void
    {
        $missingKey = __DIR__ . '/../../fixtures/missing-key-' . uniqid('', true) . '.pem';
        $configFile = $this->createConfigForKeyPath($missingKey);

        try {
            $tester = $this->createCommandTester();
            $tester->execute([
                'config-path' => $configFile,
                '--check-keys' => true,
            ]);

            $this->assertSame(1, $tester->getStatusCode());
            $this->assertStringContainsString('file not found', strtolower($tester->getDisplay()));
        } finally {
            $this->deleteScratchFile($configFile);
        }
    }

    public function testCheckKeysReturnsFailureForEcPrivateKey(): void
    {
        $keyFile    = $this->createPrivateKeyFile(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $configFile = $this->createConfigForKeyPath($keyFile);

        try {
            $tester = $this->createCommandTester();
            $tester->execute([
                'config-path' => $configFile,
                '--check-keys' => true,
            ]);

            $this->assertSame(1, $tester->getStatusCode());
            $this->assertStringContainsString('not an rsa private key', strtolower($tester->getDisplay()));
        } finally {
            $this->deleteScratchFile($configFile);
            $this->deleteScratchFile($keyFile);
        }
    }

    private function createCommandTester(): CommandTester
    {
        $command = new ValidateConfigCommand();
        $app     = new Application();
        $app->add($command);

        return new CommandTester($command);
    }

    private function createConfigForKeyPath(string $keyPath): string
    {
        return $this->createConfigFile(sprintf(
            <<<'YAML'
agent_name: test-agent
keys:
  - name: k1
    key_path: %s
    operations: [sign]
clients:
  - name: c1
    token: test-token-value-at-least-32-chars-long
    allowed_keys: [k1]
YAML,
            $keyPath,
        ));
    }

    private function createConfigFile(string $contents): string
    {
        $path = __DIR__ . '/../../fixtures/validate-config-' . uniqid('', true) . '.yaml';
        file_put_contents($path, $contents);

        return $path;
    }

    /** @param array<string, int|string> $options */
    private function createPrivateKeyFile(array $options): string
    {
        $privateKey = openssl_pkey_new($options);
        $this->assertNotFalse($privateKey);

        $pem = '';
        $this->assertTrue(openssl_pkey_export($privateKey, $pem));

        $path = __DIR__ . '/../../fixtures/validate-key-' . uniqid('', true) . '.pem';
        file_put_contents($path, $pem);

        return $path;
    }

    private function deleteScratchFile(string $path): void
    {
        if (! file_exists($path)) {
            return;
        }

        unlink($path);
    }
}
