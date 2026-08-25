<?php

declare(strict_types=1);

use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Path\PathGuard;
use Prism\Workspace\Security\EscapeAttempt;
use Prism\Workspace\Security\EscapeCorpus;

dataset('escape attempts', function () {
    foreach (EscapeCorpus::all() as $case) {
        yield $case->id => [$case];
    }
});

it('refuses every attempt in the corpus, with the code the corpus names', function (EscapeAttempt $case): void {
    $guard = new PathGuard;

    try {
        $accepted = $guard->guard($case->path);
    } catch (PathRefused $refused) {
        // The code, not merely A code. Which refusal fires is part of the
        // contract: a consumer alerting on "an agent tried to leave its
        // workspace" needs traversal and "the name has a trailing dot" to be
        // distinguishable, and an ordering change that silently reclassifies
        // one as the other would break that alert without failing a test that
        // only asserted "it threw".
        expect($refused->refusal)->toBe(
            $case->refusal,
            "[{$case->id}] {$case->printable()} was refused as [{$refused->refusal->value}], ".
            "but the corpus says [{$case->refusal->value}]."
        );

        return;
    }

    throw new Exception(
        "[{$case->id}] {$case->printable()} was ACCEPTED and normalised to [{$accepted}]. ".
        "The corpus says it should have been refused as [{$case->refusal->value}]."
    );
})->with('escape attempts');

it('accepts and normalises paths an agent legitimately writes', function (string $input, string $expected): void {
    expect((new PathGuard)->guard($input))->toBe($expected);
})->with([
    'a plain file' => ['report.md', 'report.md'],
    'a nested file' => ['reports/2026/q1.csv', 'reports/2026/q1.csv'],
    'a dotfile' => ['.gitignore', '.gitignore'],
    'a dot directory' => ['.cache/index.json', '.cache/index.json'],
    'several extensions' => ['archive.tar.gz', 'archive.tar.gz'],
    'accented characters' => ['résumé.pdf', 'résumé.pdf'],
    'a non-latin script' => ['데이터.json', '데이터.json'],
    'an emoji' => ['notes 🎉.md', 'notes 🎉.md'],
    'interior spaces' => ['Q1 revenue report.xlsx', 'Q1 revenue report.xlsx'],
    'a leading current-directory marker' => ['./report.md', 'report.md'],
    'an interior no-op segment' => ['sub/./file.txt', 'sub/file.txt'],
    'a doubled separator' => ['sub//file.txt', 'sub/file.txt'],
    'a trailing separator' => ['reports/', 'reports'],

    // A backslash is a legal filename character on Linux and a separator on
    // Windows. One input has to get one answer, so it is always a separator —
    // which costs Linux users a filename nobody should want, and buys a
    // workspace that means the same thing on both platforms.
    'a backslash, folded to a separator' => ['reports\\q1.csv', 'reports/q1.csv'],

    // The device-name list must match a NAME, not a prefix. These three are
    // the difference between a guard and a nuisance.
    'a name beginning with CON' => ['CONTRACT.md', 'CONTRACT.md'],
    'a name beginning with NUL' => ['nullify.txt', 'nullify.txt'],
    'a name beginning with AUX' => ['AUXILIARY/notes.md', 'AUXILIARY/notes.md'],

    // COM0 through COM9 are devices. COM10 is a file.
    'a device name with one digit too many' => ['COM10', 'COM10'],

    // The home-expansion rule fires on a leading segment that is `~` plus
    // word characters. This is what Word leaves behind, and it is a file.
    'a Word lock file' => ['~$quarterly.docx', '~$quarterly.docx'],
]);

it('normalises to a fixed point', function (): void {
    $guard = new PathGuard;

    foreach (['./sub//./file.txt', 'reports\\2026\\q1.csv', 'a/b/c.md'] as $input) {
        $once = $guard->guard($input);

        expect($guard->guard($once))->toBe($once);
    }
});

it('answers a question about a string without asking the filesystem', function (): void {
    // The stated performance requirement: path resolution happens on every
    // operation and must not stat the disk to answer a question about a
    // string. Asserted by reading the source rather than by timing it, because
    // a timing test is a flake and this is a fact about the code.
    //
    // The symlink boundary DOES touch the filesystem — a link is not a
    // property of a string — and lives in LocalBoundary for exactly that
    // reason, so that this class can be held to this rule.
    $source = file_get_contents((new ReflectionClass(PathGuard::class))->getFileName() ?: '');

    // Comments stripped, because the docblock has to be free to EXPLAIN why
    // there is no realpath here without that explanation failing the test.
    $code = '';

    foreach (token_get_all((string) $source) as $token) {
        $code .= is_array($token)
            ? (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1])
            : $token;
    }

    foreach (['file_exists', 'is_dir', 'is_file', 'realpath', 'is_link', 'readlink', 'scandir', 'glob', 'fopen', 'stat('] as $call) {
        expect($code)->not->toContain($call);
    }
});

it('reports the offending path on the exception, so a log has something to alert on', function (): void {
    try {
        (new PathGuard)->guard('../../etc/passwd');
    } catch (PathRefused $refused) {
        expect($refused->refusal->value)->toBe('path_traverses_outside_workspace')
            ->and($refused->path)->toBe('../../etc/passwd');

        return;
    }

    throw new Exception('Expected a refusal.');
});
