<?php

declare(strict_types=1);

use Prism\Workspace\Security\EscapeAttempt;
use Prism\Workspace\Security\EscapeCorpus;
use Prism\Workspace\Security\Unguarded;
use Tests\Support\NaiveResolver;

/**
 * The corpus, watched failing.
 *
 * A guard nobody has seen fail is a hypothesis. This file is where the failure
 * is watched — and it stays watched, which is the part that matters. Observing
 * a red suite once, before writing the guard, proves something about an
 * afternoon; a permanent test proving the same thing proves it on every commit
 * for as long as the package exists.
 *
 * What it asserts, per case and per platform: an attempt classified as
 * `Escapes` DOES leave the root when nothing is guarding it, and an attempt
 * classified as anything else does NOT. Both directions are load-bearing. The
 * first stops the corpus filling up with harmless strings that make the guard
 * look busy. The second stops a case being quietly overclaimed as an escape
 * when it is really a naming problem — the corpus is worth less if its
 * classifications are decorative.
 *
 * Both platform models run on both platforms, deliberately. Gating the Windows
 * claims behind `PHP_OS_FAMILY` would mean the Linux job never checked them,
 * and a claim only one job checks is a claim that rots in the job nobody looks
 * at.
 */
const POSIX_ROOT = '/srv/app/storage/app/workspaces/w-8f14e45fceea167a';

const WINDOWS_ROOT = 'C:/srv/app/storage/app/workspaces/w-8f14e45fceea167a';

function rootFor(string $platform): string
{
    return $platform === NaiveResolver::WINDOWS ? WINDOWS_ROOT : POSIX_ROOT;
}

function expectedOutcome(EscapeAttempt $case, string $platform): Unguarded
{
    return $platform === NaiveResolver::WINDOWS ? $case->onWindows : $case->onPosix;
}

dataset('unguarded attempts', function () {
    foreach (EscapeCorpus::all() as $case) {
        foreach (NaiveResolver::platforms() as $platform) {
            yield "{$case->id} on {$platform}" => [$case, $platform];
        }
    }
});

it('does what the corpus claims when nothing is guarding the workspace', function (EscapeAttempt $case, string $platform): void {
    $root = rootFor($platform);
    $resolved = NaiveResolver::resolve($root, $case->path, $platform);
    $inside = NaiveResolver::inside($root, $resolved, $platform);

    $escapes = expectedOutcome($case, $platform) === Unguarded::Escapes;

    expect($inside)->toBe(
        ! $escapes,
        $escapes
            ? "[{$case->id}] is classified as escaping on {$platform}, but an unguarded join kept it inside the workspace. ".
              "Either the classification is wrong or the case is not worth its line: {$case->printable()} resolved to {$resolved}."
            : "[{$case->id}] is NOT classified as escaping on {$platform}, and an unguarded join let it out anyway. ".
              "The corpus is understating this case: {$case->printable()} resolved to {$resolved}."
    );
})->with('unguarded attempts');

it('contains attempts that genuinely escape, on both platforms', function (string $platform): void {
    $escaping = array_filter(
        EscapeCorpus::all(),
        fn (EscapeAttempt $case): bool => expectedOutcome($case, $platform) === Unguarded::Escapes,
    );

    // A floor rather than an exact count, so adding cases does not fail this,
    // but deleting the teeth out of the corpus does.
    expect(count($escaping))->toBeGreaterThanOrEqual(20);
})->with(NaiveResolver::platforms());

it('classifies the platform-specific spellings differently, which is why CI runs on both', function (): void {
    $divergent = array_filter(
        EscapeCorpus::all(),
        fn (EscapeAttempt $case): bool => $case->onPosix !== $case->onWindows,
    );

    // `..\secret.txt` is a filename on Linux and an escape on Windows. A guard
    // proven only on Linux never meets the second reading, and the file it
    // happily stored becomes an escape when the disk is opened by a Windows
    // worker. If this ever drops to zero, someone has flattened the corpus onto
    // one platform.
    expect(count($divergent))->toBeGreaterThanOrEqual(20);
});

it('gives every attempt a unique, well-formed id and a reason to exist', function (): void {
    $ids = array_map(fn (EscapeAttempt $case): string => $case->id, EscapeCorpus::all());

    expect($ids)->toHaveCount(count(array_unique($ids)));

    foreach (EscapeCorpus::all() as $case) {
        expect($case->id)->toMatch('/^[a-z]{3}-\d{4}$/');

        // Borrowed from the parity loader, which refuses a case with no note
        // at load time. An undocumented case cannot be deleted on purpose,
        // only forgotten, and a corpus nobody dares prune grows until nobody
        // reads it.
        //
        // Presence only, no minimum length. A length floor is how a suite
        // starts asking for filler: "The printer." is the entire truth about
        // `PRN` and padding it would make the corpus worse, not better.
        expect(trim($case->note))->not->toBe('');
    }
});

it('keeps ids sorted within their group', function (): void {
    $groups = [];

    foreach (EscapeCorpus::all() as $case) {
        $groups[substr($case->id, 0, 3)][] = $case->id;
    }

    foreach ($groups as $prefix => $ids) {
        $sorted = $ids;
        sort($sorted);

        expect($ids)->toBe($sorted, "The [{$prefix}] group is out of order, which makes a missing id invisible.");
    }
});
