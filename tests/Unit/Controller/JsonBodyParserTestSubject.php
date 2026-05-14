<?php

declare(strict_types=1);

namespace OpenConext\PrivateKeyAgent\Tests\Unit\Controller;

use OpenConext\PrivateKeyAgent\Controller\JsonBodyParser;

/** @internal Exposes the private trait method for testing */
final class JsonBodyParserTestSubject
{
    use JsonBodyParser {
        parseJsonBody as public;
    }
}
