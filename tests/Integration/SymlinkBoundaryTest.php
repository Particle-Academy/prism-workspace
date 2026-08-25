<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Access\Gate;
use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Exceptions\Refusal;
use Prism\Workspace\Facades\PrismWorkspace;
use Prism\Workspace\Path\PathGuard;
use Prism\Workspace\Support\Authorizer;
use Prism\Workspace\Workspace;

/**
 * The escape a string cannot express.
 *
 * `reports/out.txt` is a flawless relative path. It stays a flawless relative
 * path when `reports` is a symlink to `/etc`. No amount of inspecting the name
 * finds that, which is why the corpus does not pretend to cover it and why
 * these tests exist separately.
 *
 * The link is created for real. Windows needs Developer Mode or an elevated
 * shell to create one, so the tests skip rather than fail where it is not
 * permitted — and say so, because a suite that silently skips its most
 * interesting case is a suite that is quietly not run.
 */
function linkOutOfWorkspace(Workspace $workspace, string $sandbox): string
{
    $outside = $sandbox.DIRECTORY_SEPARATOR.'outside';

    if (! is_dir($outside)) {
        mkdir($outside, 0777, true);
    }

    file_put_contents($outside.DIRECTORY_SEPARATOR.'secret.txt', 'the loot');

    $link = (string) $workspace->root().DIRECTORY_SEPARATOR.'reports';

    if (! is_link($link) && ! @symlink($outside, $link)) {
        test()->markTestSkipped('This platform will not let the test create a symlink (Windows needs Developer Mode or an elevated shell).');
    }

    return $outside;
}

it('lets a link out of the workspace through when the boundary is removed', function (): void {
    $workspace = PrismWorkspace::for('linked');
    $workspace->write('seed.txt', 'x');

    linkOutOfWorkspace($workspace, $this->sandbox);

    // The same workspace, same guard, same disk — with the link boundary taken
    // out. This is the failure being watched: `reports/secret.txt` passes every
    // string check there is, and reads a file from outside the workspace.
    $unbounded = new Workspace(
        address: $workspace->address(),
        disk: $workspace->disk(),
        guard: new PathGuard,
        authorizer: new Authorizer(app(Gate::class), false, 'workspace'),
        boundary: null,
    );

    expect($unbounded->read('reports/secret.txt'))->toBe('the loot');
});

it('refuses to read through a link that leaves the workspace', function (): void {
    $workspace = PrismWorkspace::for('linked');
    $workspace->write('seed.txt', 'x');

    linkOutOfWorkspace($workspace, $this->sandbox);

    try {
        $workspace->read('reports/secret.txt');
    } catch (PathRefused $refused) {
        expect($refused->refusal)->toBe(Refusal::EscapesViaLink);

        return;
    }

    throw new Exception('The workspace read a file from outside itself.');
});

it('refuses to write through a link that leaves the workspace', function (): void {
    $workspace = PrismWorkspace::for('linked');
    $workspace->write('seed.txt', 'x');

    $outside = linkOutOfWorkspace($workspace, $this->sandbox);

    try {
        // A file that does not exist yet, so there is nothing to resolve — the
        // escape belongs to the PARENT, and the boundary has to walk up to find
        // it. Getting this wrong is how a guard passes every read test and
        // still lets an agent plant a file anywhere.
        $workspace->write('reports/planted.txt', 'planted');
    } catch (PathRefused $refused) {
        expect($refused->refusal)->toBe(Refusal::EscapesViaLink)
            ->and(file_exists($outside.DIRECTORY_SEPARATOR.'planted.txt'))->toBeFalse();

        return;
    }

    throw new Exception('The workspace wrote a file outside itself.');
});

it('leaves a link that stays inside the workspace alone', function (): void {
    $workspace = PrismWorkspace::for('linked');
    $workspace->write('real/notes.md', 'inside');

    $root = (string) $workspace->root();
    $link = $root.DIRECTORY_SEPARATOR.'shortcut';

    if (! @symlink($root.DIRECTORY_SEPARATOR.'real', $link)) {
        test()->markTestSkipped('This platform will not let the test create a symlink.');
    }

    // The check is containment, not "is anything here a link". Refusing every
    // link would be easier and would break an ordinary layout for no gain: a
    // link that lands inside the workspace has not left it.
    expect($workspace->read('shortcut/notes.md'))->toBe('inside');
});
