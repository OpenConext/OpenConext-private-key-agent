<?php

declare(strict_types=1);

namespace App\Backend;

use App\Config\BackendGroupConfig;
use Psr\Log\LoggerInterface;

interface BackendTypeFactoryInterface
{
    /** Returns the backend type string this factory handles (e.g. 'openssl'). */
    public function supports(string $type): bool;

    public function createSigningBackend(BackendGroupConfig $config, LoggerInterface $logger): SigningBackendInterface;

    public function createDecryptionBackend(BackendGroupConfig $config, LoggerInterface $logger): DecryptionBackendInterface;
}
