<?php

declare(strict_types=1);

namespace Prism\Workspace\Exceptions;

use RuntimeException;

/**
 * An operation on a workspace did not work.
 *
 * The path was fine — see {@see PathRefused} for the other case. Carries a
 * {@see Fault} because prose is not the contract; decision 0004.
 */
final class WorkspaceFailed extends RuntimeException
{
    public function __construct(
        public readonly Fault $fault,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function make(Fault $fault, string $message): self
    {
        return new self($fault, $message);
    }
}
