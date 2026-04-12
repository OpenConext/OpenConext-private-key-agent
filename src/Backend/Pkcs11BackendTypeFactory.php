<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.backend_type_factory')]
final class Pkcs11BackendTypeFactory implements BackendTypeFactoryInterface
{
    public function supports(string $type): bool
    {
        return $type === 'pkcs11';
    }

    public function createSigningBackend(BackendGroupConfig $config): SigningBackendInterface
    {
        return new Pkcs11SigningBackend($config);
    }

    public function createDecryptionBackend(BackendGroupConfig $config): DecryptionBackendInterface
    {
        return new Pkcs11DecryptionBackend($config);
    }
}
