<?php

declare(strict_types=1);

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Storage;
use Prism\Workspace\Security\EscapeCorpus;
use Prism\Workspace\Security\Hazard;

/**
 * What a Laravel disk does with the corpus, with no guard in front of it.
 *
 * This file exists because the alternative is overclaiming. It is tempting to
 * present a workspace package as the thing standing between an agent and
 * `../../etc/passwd`. It is not: Flysystem's own normaliser already refuses
 * `..`, and it refuses every Unicode format and control character too. A
 * security package that implied otherwise would be keeping a marketing claim in
 * the worst possible place.
 *
 * So the gap is MEASURED, and pinned here — a Flysystem release that closes
 * more of it should fail this build and make somebody restate the argument,
 * rather than leaving the README quietly wrong.
 *
 * Measured on Windows 11 / PHP 8.4, bare `league/flysystem` local adapter,
 * 134 attempts:
 *
 *   46  refused by FLYSYSTEM — 22 traversal, 24 corrupted-path (Unicode
 *       category C and invalid UTF-8). Portable, and genuinely good.
 *   24  refused by the OPERATING SYSTEM, not by any guard — trailing dots,
 *       edge spaces, over-long names. Platform-dependent by definition: most
 *       of these are legal filenames on Linux.
 *   64  ACCEPTED. Device names, alternate data streams, 8.3 aliases, every
 *       percent-encoding, separator homoglyphs, `~/.ssh/id_rsa`, and every
 *       absolute path — silently relocated inside the root rather than
 *       refused.
 */
function bareDisk(string $root): Filesystem
{
    return Storage::build(['driver' => 'local', 'root' => $root, 'throw' => true]);
}

function bareDiskAccepts(Filesystem $disk, string $path): bool
{
    try {
        $disk->put($path, 'M');

        return true;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @return list<string>
 */
function bareDiskAccepted(string $root): array
{
    $disk = bareDisk($root);

    return array_values(array_map(
        fn ($attempt): string => $attempt->id,
        array_filter(EscapeCorpus::all(), fn ($attempt): bool => bareDiskAccepts($disk, $attempt->path)),
    ));
}

it('gives Flysystem credit for the traversal it already stops', function (): void {
    $disk = bareDisk($this->diskRoot.DIRECTORY_SEPARATOR.'bare');

    foreach (EscapeCorpus::withHazard(Hazard::Traversal) as $attempt) {
        if (! str_starts_with($attempt->path, '..') || str_contains($attempt->path, ';')) {
            continue;
        }

        expect(bareDiskAccepts($disk, $attempt->path))->toBeFalse(
            "Flysystem used to refuse [{$attempt->id}] and no longer does."
        );
    }
});

it('gives Flysystem credit for the invisible characters it already stops', function (): void {
    $disk = bareDisk($this->diskRoot.DIRECTORY_SEPARATOR.'bare');

    // Flysystem matches \p{C} — every Unicode control and format character —
    // which covers the whole byte-injection group and every invisible in the
    // deception group. It does NOT cover the separator homoglyphs, because a
    // fullwidth solidus is punctuation and perfectly well-formed.
    foreach (['byt-0001', 'byt-0005', 'byt-0010', 'dec-0001', 'dec-0009', 'dec-0011'] as $id) {
        expect(bareDiskAccepts($disk, EscapeCorpus::get($id)->path))->toBeFalse(
            "Flysystem used to refuse [{$id}] and no longer does."
        );
    }
});

it('measures the gap this package actually fills', function (): void {
    $accepted = bareDiskAccepted($this->diskRoot.DIRECTORY_SEPARATOR.'bare');

    // 64 of 134 on Windows and more on Linux, where most of the names the OS
    // rejects are legal. A floor, so the two platforms can differ without this
    // becoming a platform check.
    expect(count($accepted))->toBeGreaterThanOrEqual(50);

    // Asserted per HAZARD rather than per case, on purpose. Which individual
    // names a bare disk swallows moves with the platform and even with the
    // Windows build — `nul.log` was accepted by raw Flysystem here and refused
    // through Laravel's disk, because Laravel asks for private visibility and
    // the chmod is what fails. Pinning an id list would make this a test about
    // that. Pinning the hazard says the thing that is actually true: the
    // framework leaves each of these classes open, and this package closes it.
    $hazardsLeftOpen = [
        Hazard::DeviceName,
        Hazard::AlternateDataStream,
        Hazard::NameAliasing,
        Hazard::EncodedSeparator,
        Hazard::Deception,
        Hazard::AbsolutePath,
        Hazard::UncPath,
    ];

    foreach ($hazardsLeftOpen as $hazard) {
        $ids = array_map(fn ($attempt): string => $attempt->id, EscapeCorpus::withHazard($hazard));

        expect(array_intersect($ids, $accepted))->not->toBeEmpty(sprintf(
            'The baseline has moved: the framework now refuses every [%s] attempt by itself, so the argument for guarding that class here needs restating.',
            $hazard->value,
        ));
    }
});

it('shows that an absolute path is relocated rather than refused', function (): void {
    $root = $this->diskRoot.DIRECTORY_SEPARATOR.'bare';

    bareDisk($root)->put('/etc/passwd', 'M');

    // Contained, and wrong. Nothing escaped — Flysystem's prefixer simply drops
    // the leading separator — but the agent asked for one thing and got another
    // with no error anywhere. That is the failure this package is arranged
    // against and the reason an absolute path is REFUSED here rather than
    // quietly reinterpreted: a successful call that did something else is worse
    // than an exception.
    expect(file_exists($root.DIRECTORY_SEPARATOR.'etc'.DIRECTORY_SEPARATOR.'passwd'))->toBeTrue();
});

it('names every hazard class in the corpus', function (): void {
    // Structural, with a purpose: the corpus is meant to be exhaustive per
    // hazard, so a hazard with no cases means somebody added a category and
    // then stopped.
    foreach (Hazard::cases() as $hazard) {
        expect(EscapeCorpus::withHazard($hazard))->not->toBeEmpty("Hazard [{$hazard->value}] has no cases.");
    }
});
