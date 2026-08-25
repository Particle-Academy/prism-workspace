<?php

declare(strict_types=1);

namespace Prism\Workspace\Exceptions;

use RuntimeException;

/**
 * A path did not survive the guard.
 *
 * Carries the machine-readable `Refusal` and the path that caused it. Both are
 * public because this is the exception somebody builds an alert on: an agent
 * attempting to leave its workspace is a security event, and an event with no
 * stable identifier is an event nobody can page on.
 *
 * The message is prose and is explicitly outside the contract — decision 0004.
 * Reword it freely; branch on `$refusal`.
 */
final class PathRefused extends RuntimeException
{
    public function __construct(
        public readonly Refusal $refusal,
        public readonly string $path,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function make(Refusal $refusal, string $path, string $because): self
    {
        return new self($refusal, $path, sprintf(
            'The workspace refused the path [%s]: %s.',
            self::printable($path),
            $because,
        ));
    }

    /**
     * Escape per byte before the path reaches a message.
     *
     * Several of the paths this class refuses are invisible or actively
     * hostile to a terminal — one is a right-to-left override, which would
     * reverse the rest of the line it is printed into, and another is an ANSI
     * clear-screen. An exception message that faithfully reproduced them would
     * hand the agent a way to edit its operator's console from inside a
     * failure.
     */
    private static function printable(string $path): string
    {
        $out = '';
        $length = strlen($path);

        for ($i = 0; $i < $length; $i++) {
            $byte = ord($path[$i]);

            $out .= ($byte < 0x20 || $byte >= 0x7F)
                ? sprintf('\x%02X', $byte)
                : $path[$i];
        }

        return $out;
    }
}
