<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.backend_type_factory')]
final class OpenSslBackendTypeFactory implements BackendTypeFactoryInterface
{
    public function supports(string $type): bool
    {
        return $type === 'openssl';
    }

    public function createSigningBackend(BackendGroupConfig $config): SigningBackendInterface
    {
        return new OpenSslSigningBackend($config);
    }

    public function createDecryptionBackend(BackendGroupConfig $config): DecryptionBackendInterface
    {
        return new OpenSslDecryptionBackend($config);
    }
}
