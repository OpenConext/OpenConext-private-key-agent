<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Controller;

use OpenConext\PrivateKeyAgent\Exception\InvalidRequestException;
use Symfony\Component\HttpFoundation\Request;

use function is_array;
use function json_decode;

trait JsonBodyParser
{
    /** @return array<string, mixed> */
    private function parseJsonBody(Request $request): array
    {
        $data = json_decode($request->getContent(), true);
        if (! is_array($data)) {
            throw new InvalidRequestException('Invalid JSON body');
        }

        return $data;
    }
}
