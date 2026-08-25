<?php

declare(strict_types=1);

use Prism\Workspace\Facades\PrismWorkspace;
use Prism\Workspace\Security\CorpusRunner;
use Prism\Workspace\Security\EscapeCorpus;

it('fires the whole corpus at a real workspace on a real disk and lands nothing', function (): void {
    $workspace = PrismWorkspace::for('agent-under-attack');
    $workspace->write('legitimate.txt', 'this should be the only file here');

    $report = (new CorpusRunner)->against($workspace);

    // The summary is attached to the failure so that a red build says WHICH
    // attempt landed and what it was refused as, rather than "false is not
    // true".
    expect($report->passed())->toBeTrue($report->summary())
        ->and($report->failures())->toBe([])
        ->and($report->strays())->toBe([])
        ->and($report->swept)->toBeTrue()
        ->and($report->results)->toHaveCount(count(EscapeCorpus::all()));

    // A passing run writes nothing, so the workspace is untouched.
    expect($workspace->list()->count())->toBe(1);
});

it('finds a stray, so that finding none means something', function (): void {
    $workspace = PrismWorkspace::for('agent-under-attack');
    $workspace->write('seed.txt', 'x');

    $marker = 'prism-workspace-escape-marker-planted-by-the-test';

    // Plant the marker where an attempt WOULD have put it if the guard had let
    // one through: one level above the workspace, in the workspaces directory.
    //
    // Without this the sweep is a check nobody has ever seen succeed, which is
    // indistinguishable from a check that cannot succeed. It is the same
    // argument the unguarded baseline makes about the corpus itself.
    $planted = dirname((string) $workspace->root()).DIRECTORY_SEPARATOR.'escaped.txt';
    file_put_contents($planted, $marker);

    $report = (new CorpusRunner)->against($workspace, $marker);

    expect($report->failures())->toBe([])
        ->and($report->strays())->toContain($planted)
        ->and($report->passed())->toBeFalse()
        ->and($report->summary())->toContain('ESCAPED THE WORKSPACE');
});
