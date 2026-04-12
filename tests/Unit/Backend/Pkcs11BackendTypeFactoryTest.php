<?php

declare(strict_types=1);

namespace App\Tests\Unit\Backend;

use App\Backend\Pkcs11BackendTypeFactory;
use App\Backend\Pkcs11DecryptionBackend;
use App\Backend\Pkcs11SigningBackend;
use App\Config\BackendGroupConfig;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

class Pkcs11BackendTypeFactoryTest extends TestCase
{
    public function testSupportsPkcs11Type(): void
    {
        $factory = new Pkcs11BackendTypeFactory();
        $this->assertTrue($factory->supports('pkcs11'));
    }

    public function testDoesNotSupportOtherTypes(): void
    {
        $factory = new Pkcs11BackendTypeFactory();
        $this->assertFalse($factory->supports('openssl'));
        $this->assertFalse($factory->supports('unknown'));
    }

    #[RequiresPhpExtension('pkcs11')]
    public function testCreateSigningBackend(): void
    {
        $config  = new BackendGroupConfig(
            name: 'hsm',
            type: 'pkcs11',
            pkcs11Lib: '/usr/lib/softhsm/libsofthsm2.so',
            pkcs11Slot: 0,
            pkcs11Pin: '1234',
            pkcs11KeyLabel: 'test',
        );
        $factory = new Pkcs11BackendTypeFactory();

        $backend = $factory->createSigningBackend($config);
        $this->assertInstanceOf(Pkcs11SigningBackend::class, $backend);
    }

    #[RequiresPhpExtension('pkcs11')]
    public function testCreateDecryptionBackend(): void
    {
        $config  = new BackendGroupConfig(
            name: 'hsm',
            type: 'pkcs11',
            pkcs11Lib: '/usr/lib/softhsm/libsofthsm2.so',
            pkcs11Slot: 0,
            pkcs11Pin: '1234',
            pkcs11KeyLabel: 'test',
        );
        $factory = new Pkcs11BackendTypeFactory();

        $backend = $factory->createDecryptionBackend($config);
        $this->assertInstanceOf(Pkcs11DecryptionBackend::class, $backend);
    }
}
