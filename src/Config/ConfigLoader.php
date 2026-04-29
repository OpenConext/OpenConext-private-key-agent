<?php

declare(strict_types=1);

namespace App\Config;

use App\Exception\InvalidConfigurationException;
use Symfony\Component\Yaml\Yaml;

use function array_diff;
use function array_unique;
use function array_values;
use function count;
use function file_exists;
use function implode;
use function is_array;
use function is_string;
use function sprintf;

final class ConfigLoader
{
    private const array VALID_OPERATIONS = ['sign', 'decrypt'];

    public static function load(string $path): AgentConfig
    {
        if (! file_exists($path)) {
            throw new InvalidConfigurationException(sprintf('Config file not found: %s', $path));
        }

        $data = Yaml::parseFile($path);

        self::validateStructure($data);

        $keys    = self::parseKeys($data['keys'] ?? []);
        $clients = self::parseClients($data['clients'] ?? []);

        return new AgentConfig(
            agentName: $data['agent_name'],
            keys: $keys,
            clients: $clients,
        );
    }

    private static function validateStructure(mixed $data): void
    {
        if (! is_array($data)) {
            throw new InvalidConfigurationException('Config file must contain a YAML mapping');
        }

        if (empty($data['agent_name']) || ! is_string($data['agent_name'])) {
            throw new InvalidConfigurationException('Config must contain a non-empty string agent_name');
        }

        if (isset($data['keys']) && ! is_array($data['keys'])) {
            throw new InvalidConfigurationException('Config "keys" must be a YAML sequence');
        }

        if (! isset($data['clients']) || ! is_array($data['clients']) || count($data['clients']) === 0) {
            throw new InvalidConfigurationException('At least one client must be configured');
        }
    }

    /**
     * @param array<mixed> $keysData
     *
     * @return list<KeyConfig>
     */
    private static function parseKeys(array $keysData): array
    {
        $keys      = [];
        $seenNames = [];

        foreach ($keysData as $keyData) {
            if (! is_array($keyData)) {
                throw new InvalidConfigurationException('Each entry under "keys" must be a YAML mapping');
            }

            $name = $keyData['name'] ?? throw new InvalidConfigurationException('Key must have a name');

            if (isset($seenNames[$name])) {
                throw new InvalidConfigurationException(sprintf('Duplicate key name: %s', $name));
            }

            $seenNames[$name] = true;

            if (empty($keyData['key_path']) || ! is_string($keyData['key_path'])) {
                throw new InvalidConfigurationException(sprintf('Key "%s" must have a key_path', $name));
            }

            $operations = $keyData['operations'] ?? [];
            if (! is_array($operations) || count($operations) === 0) {
                throw new InvalidConfigurationException(sprintf('Key "%s" must have at least one operation', $name));
            }

            $unknown = array_diff(array_unique($operations), self::VALID_OPERATIONS);
            if (count($unknown) > 0) {
                throw new InvalidConfigurationException(sprintf(
                    'Key "%s" has unknown operation(s): %s. Valid: sign, decrypt',
                    $name,
                    implode(', ', $unknown),
                ));
            }

            $keys[] = new KeyConfig(
                name: $name,
                keyPath: $keyData['key_path'],
                operations: array_values($operations),
            );
        }

        return $keys;
    }

    /**
     * @param array<mixed> $clientsData
     *
     * @return list<ClientConfig>
     */
    private static function parseClients(array $clientsData): array
    {
        $clients = [];
        foreach ($clientsData as $clientData) {
            if (! is_array($clientData)) {
                throw new InvalidConfigurationException('Each entry under "clients" must be a YAML mapping');
            }

            $name  = $clientData['name'] ?? throw new InvalidConfigurationException('Client must have a name');
            $token = $clientData['token'] ?? throw new InvalidConfigurationException(sprintf('Client "%s" must have a token', $name));

            if (! is_string($token) || $token === '') {
                throw new InvalidConfigurationException(sprintf('Client "%s" token must be a non-empty string', $name));
            }

            $clients[] = new ClientConfig(
                name: $name,
                token: $token,
                allowedKeys: $clientData['allowed_keys'] ?? [],
            );
        }

        return $clients;
    }
}
