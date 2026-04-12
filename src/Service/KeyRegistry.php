<?php

declare(strict_types=1);

namespace App\Service;

use App\Backend\BackendInterface;
use App\Backend\DecryptionBackendInterface;
use App\Backend\SigningBackendInterface;
use App\Exception\InvalidConfigurationException;
use App\Exception\InvalidRequestException;
use Psr\Log\LoggerInterface;

use function array_keys;
use function array_unique;
use function count;
use function spl_object_id;
use function sprintf;

final class KeyRegistry implements KeyRegistryInterface
{
    /** @var array<string, list<SigningBackendInterface>> */
    private array $signingBackends = [];

    /** @var array<string, list<DecryptionBackendInterface>> */
    private array $decryptionBackends = [];

    /** @var array<string, int> */
    private array $signingCounters = [];

    /** @var array<string, int> */
    private array $decryptionCounters = [];

    /** @var array<string, true> */
    private array $fingerprintCheckedSigning = [];

    /** @var array<string, true> */
    private array $fingerprintCheckedDecryption = [];

    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    public function registerSigningBackend(string $keyName, SigningBackendInterface $backend): void
    {
        $this->signingBackends[$keyName][] = $backend;
    }

    public function registerDecryptionBackend(string $keyName, DecryptionBackendInterface $backend): void
    {
        $this->decryptionBackends[$keyName][] = $backend;
    }

    /**
     * Returns the next signing backend for the given key name (round-robin).
     *
     * @throws InvalidRequestException If no signing backend is registered for the key.
     */
    public function getSigningBackend(string $keyName): SigningBackendInterface
    {
        if (! isset($this->signingBackends[$keyName]) || count($this->signingBackends[$keyName]) === 0) {
            throw new InvalidRequestException(sprintf('No signing backend registered for key "%s"', $keyName));
        }

        $backends = $this->signingBackends[$keyName];

        if (count($backends) > 1 && ! isset($this->fingerprintCheckedSigning[$keyName])) {
            $this->assertFingerprintsMatch($backends, $keyName);
            $this->fingerprintCheckedSigning[$keyName] = true;
        }

        $index                           = ($this->signingCounters[$keyName] ?? 0) % count($backends);
        $this->signingCounters[$keyName] = $index + 1;

        return $backends[$index];
    }

    /**
     * Returns the next decryption backend for the given key name (round-robin).
     *
     * @throws InvalidRequestException If no decryption backend is registered for the key.
     */
    public function getDecryptionBackend(string $keyName): DecryptionBackendInterface
    {
        if (! isset($this->decryptionBackends[$keyName]) || count($this->decryptionBackends[$keyName]) === 0) {
            throw new InvalidRequestException(sprintf('No decryption backend registered for key "%s"', $keyName));
        }

        $backends = $this->decryptionBackends[$keyName];

        if (count($backends) > 1 && ! isset($this->fingerprintCheckedDecryption[$keyName])) {
            $this->assertFingerprintsMatch($backends, $keyName);
            $this->fingerprintCheckedDecryption[$keyName] = true;
        }

        $index                              = ($this->decryptionCounters[$keyName] ?? 0) % count($backends);
        $this->decryptionCounters[$keyName] = $index + 1;

        return $backends[$index];
    }

    /** @return list<string> */
    public function getSigningKeyNames(): array
    {
        return array_keys($this->signingBackends);
    }

    /** @return list<string> */
    public function getDecryptionKeyNames(): array
    {
        return array_keys($this->decryptionBackends);
    }

    /** @return list<SigningBackendInterface> */
    public function getAllSigningBackends(string $keyName): array
    {
        return $this->signingBackends[$keyName] ?? [];
    }

    /** @return list<DecryptionBackendInterface> */
    public function getAllDecryptionBackends(string $keyName): array
    {
        return $this->decryptionBackends[$keyName] ?? [];
    }

    /** @return list<BackendInterface> */
    public function getAllBackends(): array
    {
        $seen   = [];
        $result = [];

        foreach ($this->signingBackends as $backends) {
            foreach ($backends as $backend) {
                $id = spl_object_id($backend);
                if (isset($seen[$id])) {
                    continue;
                }

                $seen[$id] = true;
                $result[]  = $backend;
            }
        }

        foreach ($this->decryptionBackends as $backends) {
            foreach ($backends as $backend) {
                $id = spl_object_id($backend);
                if (isset($seen[$id])) {
                    continue;
                }

                $seen[$id] = true;
                $result[]  = $backend;
            }
        }

        return $result;
    }

    /** @return list<BackendInterface> */
    public function getBackendsByName(string $backendName): array
    {
        $seen   = [];
        $result = [];

        foreach ($this->signingBackends as $backends) {
            foreach ($backends as $backend) {
                if ($backend->getName() !== $backendName) {
                    continue;
                }

                $id = spl_object_id($backend);
                if (isset($seen[$id])) {
                    continue;
                }

                $seen[$id] = true;
                $result[]  = $backend;
            }
        }

        foreach ($this->decryptionBackends as $backends) {
            foreach ($backends as $backend) {
                if ($backend->getName() !== $backendName) {
                    continue;
                }

                $id = spl_object_id($backend);
                if (isset($seen[$id])) {
                    continue;
                }

                $seen[$id] = true;
                $result[]  = $backend;
            }
        }

        return $result;
    }

    /**
     * @param list<BackendInterface> $backends
     *
     * @throws InvalidConfigurationException
     */
    private function assertFingerprintsMatch(array $backends, string $keyName): void
    {
        $fingerprints = [];
        foreach ($backends as $backend) {
            $fingerprints[$backend->getName()] = $backend->getPublicKeyFingerprint();
        }

        if (count(array_unique($fingerprints)) > 1) {
            $this->logger->error('Key equivalence check failed: backends hold different key material', [
                'key'          => $keyName,
                'fingerprints' => $fingerprints,
            ]);

            throw new InvalidConfigurationException(sprintf(
                'Backends for key "%s" hold different key material (fingerprint mismatch)',
                $keyName,
            ));
        }
    }
}
