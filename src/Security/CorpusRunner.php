<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

use FilesystemIterator;
use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Workspace;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Throwable;

/**
 * Fires the whole corpus at a real workspace and reports what happened.
 *
 *     $report = (new CorpusRunner)->against(PrismWorkspace::for($session));
 *
 *     if (! $report->passed()) {
 *         throw new RuntimeException($report->summary());
 *     }
 *
 * This is the class that makes the package's central claim checkable by someone
 * who does not trust it. Our CI proves the boundary holds on our disk
 * configuration; yours might use a different driver, a different root, a
 * network share, a case-insensitive volume, `'links' => 'skip'` — and a security
 * property is only true of the configuration it was measured on. So the corpus
 * ships, and you can measure yours.
 *
 * It is safe to run against a live workspace: every attempt is expected to be
 * refused, so a passing run writes nothing at all. The marker is per-run and
 * random, so a stray found afterwards is unambiguously from THIS run.
 *
 * ## Two checks, not one
 *
 * Every attempt is refused with the code the corpus names — and then the
 * directories AROUND the workspace are swept for the marker. The second is the
 * one that would catch a mistake the first cannot: a guard that refuses
 * everything correctly and a workspace whose root was assembled wrongly would
 * pass every unit test in the package and still be writing into the wrong
 * place.
 */
final class CorpusRunner
{
    /** How many levels above the workspace to sweep. */
    private const SWEEP_LEVELS = 3;

    /** A ceiling, so a sweep of a large disk cannot become the slowest thing in a test suite. */
    private const SWEEP_FILE_LIMIT = 20000;

    /**
     * @param  string|null  $marker  Override the per-run marker. For testing the
     *                               runner itself — planting a known marker
     *                               outside the workspace is the only way to
     *                               prove the sweep can find one, and a sweep
     *                               that has never found anything is not a
     *                               check, it is a habit.
     */
    public function against(Workspace $workspace, ?string $marker = null): CorpusReport
    {
        $marker ??= 'prism-workspace-escape-marker-'.bin2hex(random_bytes(16));

        $results = [];

        foreach (EscapeCorpus::all() as $attempt) {
            $results[] = $this->attempt($workspace, $attempt, $marker);
        }

        $root = $workspace->root();

        return new CorpusReport(
            results: $results,
            strays: $root === null ? [] : $this->sweep($root, $marker),
            swept: $root !== null,
        );
    }

    private function attempt(Workspace $workspace, EscapeAttempt $attempt, string $marker): CorpusResult
    {
        try {
            $workspace->write($attempt->path, $marker);
        } catch (PathRefused $refused) {
            return $refused->refusal === $attempt->refusal
                ? new CorpusResult($attempt, CorpusOutcome::Refused, $refused->refusal, 'refused as expected')
                : new CorpusResult($attempt, CorpusOutcome::WrongCode, $refused->refusal, sprintf(
                    'refused as [%s], expected [%s]',
                    $refused->refusal->value,
                    $attempt->refusal->value,
                ));
        } catch (Throwable $error) {
            // Not a pass. Something failed for a reason the boundary did not
            // choose, which means the boundary was not what stopped it — and on
            // a differently configured disk it might not stop it at all.
            return new CorpusResult($attempt, CorpusOutcome::Errored, null, sprintf(
                'threw %s: %s',
                $error::class,
                $error->getMessage(),
            ));
        }

        return new CorpusResult($attempt, CorpusOutcome::Accepted, null, sprintf(
            'was ACCEPTED; expected refusal [%s]',
            $attempt->refusal->value,
        ));
    }

    /**
     * @return list<string>
     */
    private function sweep(string $root, string $marker): array
    {
        $top = $root;

        for ($level = 0; $level < self::SWEEP_LEVELS; $level++) {
            $parent = dirname($top);

            if ($parent === $top) {
                break;
            }

            $top = $parent;
        }

        $strays = [];
        $seen = 0;
        $length = strlen($marker);

        try {
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($top, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY,
                RecursiveIteratorIterator::CATCH_GET_CHILD,
            );

            /** @var SplFileInfo $file */
            foreach ($files as $file) {
                if (++$seen > self::SWEEP_FILE_LIMIT) {
                    break;
                }

                // The marker is the whole content of anything an attempt wrote,
                // so anything the wrong size cannot be one. That check is what
                // keeps this from reading an entire storage directory.
                if (! $file->isFile() || $file->getSize() !== $length) {
                    continue;
                }

                if (@file_get_contents($file->getPathname()) === $marker) {
                    $strays[] = $file->getPathname();
                }
            }
        } catch (Throwable) {
            // A directory we cannot read is not evidence of an escape, and a
            // sweep that throws would turn an unreadable sibling directory into
            // a failed security check.
        }

        return $strays;
    }
}
