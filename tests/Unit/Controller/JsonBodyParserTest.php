<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Controller;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

use function json_encode;

use const JSON_THROW_ON_ERROR;

class JsonBodyParserTest extends TestCase
{
    private JsonBodyParserTestSubject $parser;

    protected function setUp(): void
    {
        $this->parser = new JsonBodyParserTestSubject();
    }

    public function testParsesValidJsonObject(): void
    {
        $payload = ['algorithm' => 'rsa-pkcs1-v1_5-sha256', 'hash' => 'abc'];
        $request = Request::create('/test', 'POST', content: json_encode($payload, JSON_THROW_ON_ERROR));

        $result = $this->parser->parseJsonBody($request);

        $this->assertSame($payload, $result);
    }

    public function testParsesEmptyObject(): void
    {
        $request = Request::create('/test', 'POST', content: '{}');

        $result = $this->parser->parseJsonBody($request);

        $this->assertSame([], $result);
    }

    public function testThrowsOnEmptyBody(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid JSON body');

        $request = Request::create('/test', 'POST', content: '');
        $this->parser->parseJsonBody($request);
    }

    public function testThrowsOnInvalidJson(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid JSON body');

        $request = Request::create('/test', 'POST', content: '{not valid json}');
        $this->parser->parseJsonBody($request);
    }

    public function testParsesNestedJsonObject(): void
    {
        $request = Request::create('/test', 'POST', content: '{"key":"value","nested":{"a":1}}');

        $result = $this->parser->parseJsonBody($request);

        $this->assertSame('value', $result['key']);
        $this->assertSame(['a' => 1], $result['nested']);
    }

    public function testThrowsOnJsonScalar(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid JSON body');

        $request = Request::create('/test', 'POST', content: '"hello"');
        $this->parser->parseJsonBody($request);
    }
}
