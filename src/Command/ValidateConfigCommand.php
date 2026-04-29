<?php

declare(strict_types=1);

namespace App\Command;

use App\Config\ConfigLoader;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

use function count;
use function sprintf;

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
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io   = new SymfonyStyle($input, $output);
        $path = $input->getArgument('config-path');

        try {
            $config = ConfigLoader::load($path);
            $io->success(sprintf(
                'Configuration is valid. Agent: "%s", %d key(s), %d client(s).',
                $config->agentName,
                count($config->keys),
                count($config->clients),
            ));

            return Command::SUCCESS;
        } catch (Throwable $e) {
            $io->error(sprintf('Configuration error: %s', $e->getMessage()));

            return Command::FAILURE;
        }
    }
}
