<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.backend_type_factory')]
final class OpenSslBackendTypeFactory implements BackendTypeFactoryInterface
{
    public function supports(string $type): bool
    {
        return $type === 'openssl';
    }

    public function createSigningBackend(BackendGroupConfig $config, LoggerInterface $logger): SigningBackendInterface
    {
        return new OpenSslSigningBackend($config, $logger);
    }

    public function createDecryptionBackend(BackendGroupConfig $config, LoggerInterface $logger): DecryptionBackendInterface
    {
        return new OpenSslDecryptionBackend($config, $logger);
    }
}
