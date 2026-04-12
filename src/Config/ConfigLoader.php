<?php

declare(strict_types=1);

namespace App\Config;

use App\Exception\InvalidConfigurationException;
use Symfony\Component\Yaml\Yaml;

use function array_values;
use function count;
use function file_exists;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

final class ConfigLoader
{
    public static function load(string $path): AgentConfig
    {
        if (! file_exists($path)) {
            throw new InvalidConfigurationException(sprintf('Config file not found: %s', $path));
        }

        $data = Yaml::parseFile($path);

        self::validateStructure($data);

        $backends = self::parseBackends($data['backend_groups'] ?? []);
        $keys     = self::parseKeys($data['keys'] ?? [], $backends);
        $clients  = self::parseClients($data['clients'] ?? []);

        self::validateNoOrphanBackends($backends, $keys);

        return new AgentConfig(
            agentName: $data['agent_name'],
            backends: array_values($backends),
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

        if (! isset($data['clients']) || ! is_array($data['clients']) || count($data['clients']) === 0) {
            throw new InvalidConfigurationException('At least one client must be configured');
        }
    }

    /**
     * @param array<mixed> $groups
     *
     * @return array<string, BackendGroupConfig> Indexed by name
     */
    private static function parseBackends(array $groups): array
    {
        $backends = [];
        foreach ($groups as $group) {
            $name = $group['name'] ?? throw new InvalidConfigurationException('Backend group must have a name');
            $type = $group['type'] ?? throw new InvalidConfigurationException(sprintf('Backend group "%s" must have a type', $name));

            if (! in_array($type, ['openssl', 'pkcs11'], true)) {
                throw new InvalidConfigurationException(sprintf('Backend group "%s" has invalid type "%s"', $name, $type));
            }

            if ($type === 'openssl' && empty($group['key_path'])) {
                throw new InvalidConfigurationException(sprintf('OpenSSL backend group "%s" must have key_path', $name));
            }

            if ($type === 'pkcs11') {
                if (empty($group['pkcs11_lib'])) {
                    throw new InvalidConfigurationException(sprintf('PKCS#11 backend group "%s" must have pkcs11_lib', $name));
                }

                if (! isset($group['pkcs11_slot'])) {
                    throw new InvalidConfigurationException(sprintf('PKCS#11 backend group "%s" must have pkcs11_slot', $name));
                }

                if (empty($group['pkcs11_key_label']) && empty($group['pkcs11_key_id'])) {
                    throw new InvalidConfigurationException(sprintf('PKCS#11 backend group "%s" must have pkcs11_key_label or pkcs11_key_id', $name));
                }
            }

            $environment = [];
            if (isset($group['environment']) && is_array($group['environment'])) {
                foreach ($group['environment'] as $envKey => $envValue) {
                    $environment[(string) $envKey] = (string) $envValue;
                }
            }

            $backends[$name] = new BackendGroupConfig(
                name: $name,
                type: $type,
                keyPath: $group['key_path'] ?? null,
                pkcs11Lib: $group['pkcs11_lib'] ?? null,
                pkcs11Slot: isset($group['pkcs11_slot']) ? (int) $group['pkcs11_slot'] : null,
                pkcs11Pin: $group['pkcs11_pin'] ?? null,
                pkcs11KeyLabel: $group['pkcs11_key_label'] ?? null,
                pkcs11KeyId: $group['pkcs11_key_id'] ?? null,
                environment: $environment,
            );
        }

        return $backends;
    }

    /**
     * @param array<mixed>                      $keysData
     * @param array<string, BackendGroupConfig> $backends
     *
     * @return list<KeyConfig>
     */
    private static function parseKeys(array $keysData, array $backends): array
    {
        $keys      = [];
        $seenNames = [];

        foreach ($keysData as $keyData) {
            $name = $keyData['name'] ?? throw new InvalidConfigurationException('Key must have a name');

            if (isset($seenNames[$name])) {
                throw new InvalidConfigurationException(sprintf('Duplicate key name: %s', $name));
            }

            $seenNames[$name] = true;

            $signingBackends    = $keyData['signing_backends'] ?? [];
            $decryptionBackends = $keyData['decryption_backends'] ?? [];

            foreach ($signingBackends as $ref) {
                if (! isset($backends[$ref])) {
                    throw new InvalidConfigurationException(sprintf('Key "%s" references unknown signing backend: %s', $name, $ref));
                }
            }

            foreach ($decryptionBackends as $ref) {
                if (! isset($backends[$ref])) {
                    throw new InvalidConfigurationException(sprintf('Key "%s" references unknown decryption backend: %s', $name, $ref));
                }
            }

            $keys[] = new KeyConfig(
                name: $name,
                signingBackends: $signingBackends,
                decryptionBackends: $decryptionBackends,
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

    /**
     * @param array<string, BackendGroupConfig> $backends
     * @param list<KeyConfig>                   $keys
     */
    private static function validateNoOrphanBackends(array $backends, array $keys): void
    {
        $referenced = [];
        foreach ($keys as $key) {
            foreach ($key->signingBackends as $ref) {
                $referenced[$ref] = true;
            }

            foreach ($key->decryptionBackends as $ref) {
                $referenced[$ref] = true;
            }
        }

        foreach ($backends as $name => $backend) {
            if (! isset($referenced[$name])) {
                throw new InvalidConfigurationException(sprintf('Backend group "%s" is not referenced by any key (orphan)', $name));
            }
        }
    }
}
