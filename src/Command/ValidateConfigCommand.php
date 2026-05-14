<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Command;

use OpenConext\PrivateKeyAgent\Config\ConfigLoader;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

use function count;
use function file_exists;
use function file_get_contents;
use function is_readable;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function sprintf;

use const OPENSSL_KEYTYPE_RSA;

#[AsCommand(
    name: 'app:validate-config',
    description: 'Validate a Private Key Agent configuration file',
)]
class ValidateConfigCommand extends Command
{
    protected function configure(): void
    {
        $this->addArgument(
            'config-path',
            InputArgument::REQUIRED,
            'Path to the YAML configuration file',
        );

        $this->addOption(
            'check-keys',
            null,
            InputOption::VALUE_NONE,
            'Also verify that key files exist, are readable, and contain a valid RSA private key',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io   = new SymfonyStyle($input, $output);
        $path = $input->getArgument('config-path');

        try {
            $config = ConfigLoader::load($path);
        } catch (Throwable $e) {
            $io->error(sprintf('Configuration error: %s', $e->getMessage()));

            return Command::FAILURE;
        }

        $io->success(sprintf(
            'Configuration is valid. Agent: "%s", %d key(s), %d client(s).',
            $config->agentName,
            count($config->keys),
            count($config->clients),
        ));

        if (! $input->getOption('check-keys')) {
            return Command::SUCCESS;
        }

        $errors = [];
        foreach ($config->keys as $keyConfig) {
            $keyErrors = $this->validateKeyFile($keyConfig->name, $keyConfig->keyPath);
            foreach ($keyErrors as $error) {
                $errors[] = $error;
            }
        }

        if ($errors !== []) {
            $io->error('Key file validation failed:');
            $io->listing($errors);

            return Command::FAILURE;
        }

        $io->success(sprintf('All %d key file(s) validated successfully.', count($config->keys)));

        return Command::SUCCESS;
    }

    /** @return list<string> */
    private function validateKeyFile(string $name, string $path): array
    {
        $errors = [];

        if (! file_exists($path)) {
            $errors[] = sprintf('Key "%s": file not found at "%s"', $name, $path);

            return $errors;
        }

        if (! is_readable($path)) {
            $errors[] = sprintf('Key "%s": file not readable at "%s"', $name, $path);

            return $errors;
        }

        $pem = file_get_contents($path);
        if ($pem === false) {
            $errors[] = sprintf('Key "%s": could not read file at "%s"', $name, $path);

            return $errors;
        }

        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            $errors[] = sprintf('Key "%s": file does not contain a valid private key', $name);

            return $errors;
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            $errors[] = sprintf('Key "%s": key is not an RSA private key', $name);
        }

        return $errors;
    }
}
