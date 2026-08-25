<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

/**
 * What happened when the corpus was fired at a real workspace.
 */
final readonly class CorpusReport
{
    /**
     * @param  list<CorpusResult>  $results
     * @param  list<string>  $strays  Files found outside the workspace carrying this run's marker.
     * @param  bool  $swept  Whether the surrounding directories could be swept at all.
     */
    public function __construct(
        public array $results,
        public array $strays,
        public bool $swept,
        public string $corpusVersion = EscapeCorpus::VERSION,
    ) {}

    public function passed(): bool
    {
        return $this->failures() === [] && $this->strays === [];
    }

    /**
     * Files found outside the workspace carrying this run's marker. Empty is
     * the only acceptable answer.
     *
     * @return list<string>
     */
    public function strays(): array
    {
        return $this->strays;
    }

    /**
     * @return list<CorpusResult>
     */
    public function failures(): array
    {
        return array_values(array_filter($this->results, fn (CorpusResult $result): bool => ! $result->passed()));
    }

    public function summary(): string
    {
        $failures = $this->failures();

        $lines = [sprintf(
            'prism-workspace escape corpus v%s: %d attempts, %d refused correctly, %d failed.',
            $this->corpusVersion,
            count($this->results),
            count($this->results) - count($failures),
            count($failures),
        )];

        $lines[] = $this->swept
            ? sprintf('Swept the surrounding directories: %d stray file(s).', count($this->strays))
            : 'Surrounding directories NOT swept — this disk does not expose a local path, so containment was checked by refusal only.';

        foreach ($failures as $failure) {
            $lines[] = '  '.$failure->describe();
        }

        foreach ($this->strays as $stray) {
            $lines[] = '  ESCAPED THE WORKSPACE: '.$stray;
        }

        return implode(PHP_EOL, $lines);
    }
}
