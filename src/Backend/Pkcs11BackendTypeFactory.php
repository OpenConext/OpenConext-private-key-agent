<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.backend_type_factory')]
final class Pkcs11BackendTypeFactory implements BackendTypeFactoryInterface
{
    public function supports(string $type): bool
    {
        return $type === 'pkcs11';
    }

    public function createSigningBackend(BackendGroupConfig $config, LoggerInterface $logger): SigningBackendInterface
    {
        return new Pkcs11SigningBackend($config, $logger);
    }

    public function createDecryptionBackend(BackendGroupConfig $config, LoggerInterface $logger): DecryptionBackendInterface
    {
        return new Pkcs11DecryptionBackend($config, $logger);
    }
}
