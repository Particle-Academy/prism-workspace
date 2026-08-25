<?php

declare(strict_types=1);

/**
 * The corpus's per-platform claims, executed against a real filesystem.
 *
 * The corpus says `secret.txt.` and `secret.txt` are the same file on Windows
 * and different files on Linux. That is either true or it is folklore, and a
 * package whose entire value is a security property should not be repeating
 * folklore. These tests measure it on whichever runner is executing them, so
 * every claim in the corpus that is platform-specific has a job that proves it.
 *
 * They already earned their place: the reserved-device-name group said a write
 * to `nul.log` is swallowed by the device and the artifact silently disappears,
 * which is what everybody says. On Windows 11 with a fully-qualified path it
 * did not reproduce — `CON` and `nul.log` were ordinary files, readable by PHP
 * and by `cmd` alike. The corpus notes were rewritten to say what was measured,
 * and the argument for refusing those names got better rather than worse: the
 * same name is a file or a device depending on which Windows and which API, and
 * an artifact whose existence depends on the reader is not an artifact.
 *
 * Where a hazard depends on a volume feature that may be switched off — 8.3
 * name generation, alternate data streams — the test skips rather than fails.
 * The corpus claims the hazard exists where the feature is on; it does not
 * claim the feature is always on.
 */
function hazardDirectory(string $sandbox): string
{
    $directory = $sandbox.DIRECTORY_SEPARATOR.'hazards';

    if (! is_dir($directory)) {
        mkdir($directory, 0777, true);
    }

    return $directory;
}

it('confirms Windows treats a trailing dot and a trailing space as the same name', function (): void {
    $directory = hazardDirectory($this->sandbox);

    file_put_contents($directory.DIRECTORY_SEPARATOR.'alias.txt', 'x');

    // ali-0001 and ali-0003: a write to `alias.txt.` overwrites a file the
    // caller believes it is not touching.
    expect(file_exists($directory.DIRECTORY_SEPARATOR.'alias.txt.'))->toBeTrue()
        ->and(file_exists($directory.DIRECTORY_SEPARATOR.'alias.txt '))->toBeTrue()
        ->and(file_exists($directory.DIRECTORY_SEPARATOR.'ALIAS.TXT'))->toBeTrue();
})->skip(PHP_OS_FAMILY !== 'Windows', 'Windows-only claim.');

it('confirms Linux treats them as different names', function (): void {
    $directory = hazardDirectory($this->sandbox);

    file_put_contents($directory.DIRECTORY_SEPARATOR.'alias.txt', 'x');

    // The other half of the same corpus claim, and the reason those cases are
    // classified `Confuses` on POSIX rather than `Reaches`: nothing is aliased
    // here, and the file is still a portability landmine the moment the
    // workspace is opened on Windows.
    expect(file_exists($directory.DIRECTORY_SEPARATOR.'alias.txt.'))->toBeFalse()
        ->and(file_exists($directory.DIRECTORY_SEPARATOR.'ALIAS.TXT'))->toBeFalse();
})->skip(PHP_OS_FAMILY === 'Windows' || PHP_OS_FAMILY === 'Darwin', 'Case-sensitive filesystems only.');

it('confirms an alternate data stream hides bytes behind a listed file', function (): void {
    $directory = hazardDirectory($this->sandbox);
    $host = $directory.DIRECTORY_SEPARATOR.'notes.txt';

    file_put_contents($host, 'visible');

    if (@file_put_contents($host.':hidden', 'secret') === false) {
        test()->markTestSkipped('This volume does not support alternate data streams.');
    }

    // ads-0001, measured. The listing shows one file at its original size, and
    // six bytes nothing in that listing accounts for are stored beside it.
    expect(file_get_contents($host.':hidden'))->toBe('secret')
        ->and(filesize($host))->toBe(7)
        ->and(scandir($directory))->not->toContain('notes.txt:hidden');
})->skip(PHP_OS_FAMILY !== 'Windows', 'NTFS-only claim.');

it('confirms an 8.3 short name reaches a file listed under a different name', function (): void {
    $directory = hazardDirectory($this->sandbox);

    mkdir($directory.DIRECTORY_SEPARATOR.'ProgramFilesLongName');
    file_put_contents($directory.DIRECTORY_SEPARATOR.'ProgramFilesLongName'.DIRECTORY_SEPARATOR.'inside.txt', 'reached');

    if (@file_get_contents($directory.DIRECTORY_SEPARATOR.'PROGRA~1'.DIRECTORY_SEPARATOR.'inside.txt') === false) {
        test()->markTestSkipped('8.3 name generation is disabled on this volume.');
    }

    // ali-0008, measured. Two names for one directory, and only one of them
    // appears in a listing — so an audit of what an agent wrote can be complete
    // and still miss how it was reached.
    expect(file_get_contents($directory.DIRECTORY_SEPARATOR.'PROGRA~1'.DIRECTORY_SEPARATOR.'inside.txt'))->toBe('reached');
})->skip(PHP_OS_FAMILY !== 'Windows', 'NTFS-only claim.');

it('confirms the two platforms disagree about a name made of dots', function (): void {
    $directory = hazardDirectory($this->sandbox);

    $written = @file_put_contents($directory.DIRECTORY_SEPARATOR.'...', 'x');

    // trv-0020, measured on both runners. Linux stores it; Windows refuses the
    // name outright. Neither is an escape, and the disagreement is the point:
    // the same agent instruction produces a file on one worker and an error on
    // another.
    PHP_OS_FAMILY === 'Windows'
        ? expect($written)->toBeFalse()
        : expect($written)->toBe(1);
});
