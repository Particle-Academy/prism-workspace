<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

use Prism\Workspace\Exceptions\Refusal;

/**
 * One adversarial path, and everything claimed about it.
 *
 * A case carries three separable claims, and the suite executes all three:
 *
 *  1. the guard refuses it, with `$refusal` and not merely with something
 *  2. an unguarded resolver does `$onPosix` / `$onWindows` with it
 *  3. the note says why the case exists, so a case can be deleted on purpose
 *     rather than because nobody remembered what it was for
 *
 * Claim 2 is the one that is easy to leave out and the one that makes the rest
 * worth anything. Without it a corpus proves the guard agrees with itself.
 */
final readonly class EscapeAttempt
{
    public function __construct(
        /** Stable and greppable. Never renumbered — a deleted case leaves a hole. */
        public string $id,
        /** Exactly the bytes an agent would hand to `write()`. */
        public string $path,
        public Hazard $hazard,
        /** The code the guard MUST refuse this with. Not "any refusal". */
        public Refusal $refusal,
        public Unguarded $onPosix,
        public Unguarded $onWindows,
        public string $note,
    ) {}

    /**
     * What an unguarded resolver does with this on the platform running now.
     */
    public function unguarded(): Unguarded
    {
        return PHP_OS_FAMILY === 'Windows' ? $this->onWindows : $this->onPosix;
    }

    /**
     * A printable rendering.
     *
     * Half of these paths are invisible bytes, and a failure report that prints
     * them raw is a failure report nobody can read — worse, one case here is a
     * right-to-left override, which would reverse the rest of the line it was
     * printed into. Escaping per BYTE rather than per character is deliberate:
     * some cases are not valid UTF-8 at all, so there is no character to print.
     */
    public function printable(): string
    {
        $out = '';
        $length = strlen($this->path);

        for ($i = 0; $i < $length; $i++) {
            $byte = ord($this->path[$i]);

            $out .= ($byte < 0x20 || $byte >= 0x7F)
                ? sprintf('\x%02X', $byte)
                : $this->path[$i];
        }

        return $out;
    }
}
