<?php

declare(strict_types=1);

namespace App\Tests\Unit\Command;

use App\Command\ValidateConfigCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

use function file_put_contents;
use function strtolower;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

class ValidateConfigCommandTest extends TestCase
{
    public function testValidConfigReturnsSuccess(): void
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
            $command = new ValidateConfigCommand();
            $app     = new Application();
            $app->add($command);

            $tester = new CommandTester($command);
            $tester->execute(['config-path' => $tmpFile]);

            $this->assertSame(0, $tester->getStatusCode());
            $this->assertStringContainsString('valid', strtolower($tester->getDisplay()));
        } finally {
            unlink($tmpFile);
        }
    }

    public function testInvalidConfigReturnsFailure(): void
    {
        $yaml    = "invalid: true\n";
        $tmpFile = tempnam(sys_get_temp_dir(), 'cfg_') . '.yaml';
        file_put_contents($tmpFile, $yaml);

        try {
            $command = new ValidateConfigCommand();
            $app     = new Application();
            $app->add($command);

            $tester = new CommandTester($command);
            $tester->execute(['config-path' => $tmpFile]);

            $this->assertSame(1, $tester->getStatusCode());
            $this->assertStringContainsString('error', strtolower($tester->getDisplay()));
        } finally {
            unlink($tmpFile);
        }
    }

    public function testMissingFileReturnsFailure(): void
    {
        $command = new ValidateConfigCommand();
        $app     = new Application();
        $app->add($command);

        $tester = new CommandTester($command);
        $tester->execute(['config-path' => '/nonexistent/path.yaml']);

        $this->assertSame(1, $tester->getStatusCode());
    }
}
