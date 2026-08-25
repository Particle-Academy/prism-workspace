<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

use Prism\Workspace\Exceptions\Refusal;

final readonly class CorpusResult
{
    public function __construct(
        public EscapeAttempt $attempt,
        public CorpusOutcome $outcome,
        public ?Refusal $actual,
        public string $detail,
    ) {}

    public function passed(): bool
    {
        return $this->outcome === CorpusOutcome::Refused;
    }

    public function describe(): string
    {
        return sprintf(
            '[%s] %-12s %s — %s',
            $this->attempt->id,
            $this->outcome->value,
            $this->attempt->printable(),
            $this->detail,
        );
    }
}
