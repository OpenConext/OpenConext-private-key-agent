<?php

declare(strict_types=1);

namespace App\Logging;

use Monolog\LogRecord;

final class ProcessIdProcessor
{
    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(extra: [
            ...$record->extra,
            'pid' => getmypid(),
        ]);
    }
}
