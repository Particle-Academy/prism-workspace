<?php

declare(strict_types=1);

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\LazyCollection;
use Prism\Workspace\Exceptions\Fault;
use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Exceptions\WorkspaceFailed;
use Prism\Workspace\Facades\PrismWorkspace;
use Prism\Workspace\WorkspaceEntry;
use Prism\Workspace\WorkspaceManager;

it('reads back what it wrote', function (): void {
    $workspace = PrismWorkspace::for('agent-1');

    $workspace->write('reports/q1.md', '# Q1');

    expect($workspace->read('reports/q1.md'))->toBe('# Q1')
        ->and($workspace->exists('reports/q1.md'))->toBeTrue()
        ->and($workspace->size('reports/q1.md'))->toBe(4);
});

it('gives two owners two workspaces', function (): void {
    PrismWorkspace::for('agent-1')->write('notes.md', 'one');
    PrismWorkspace::for('agent-2')->write('notes.md', 'two');

    expect(PrismWorkspace::for('agent-1')->read('notes.md'))->toBe('one')
        ->and(PrismWorkspace::for('agent-2')->read('notes.md'))->toBe('two');
});

it('resolves the same owner to the same workspace from a fresh manager', function (): void {
    PrismWorkspace::for('agent-1')->write('notes.md', 'persisted');

    // The address is derived, never stored, so a worker that has never seen
    // this owner before lands on the same directory. That is the same property
    // the harness needs from a session key, and for the same reason: a fresh
    // process has to find the work the last one left.
    app()->forgetInstance(WorkspaceManager::class);
    PrismWorkspace::clearResolvedInstances();

    expect(PrismWorkspace::for('agent-1')->read('notes.md'))->toBe('persisted');
});

it('addresses a workspace by anything with a key, which is what a harness session is', function (): void {
    $session = new class
    {
        public function key(): string
        {
            return 'session:8f14e45fce:42:coding';
        }
    };

    $workspace = PrismWorkspace::for($session);

    // A colon is illegal in a Windows filename, so a harness session key cannot
    // be a directory name as it stands. It is slugged for the human and hashed
    // for correctness.
    expect($workspace->address())->not->toContain(':')
        ->and($workspace->address())->toStartWith('session-8f14e45fce-42-coding-');

    $workspace->write('plan.md', 'ok');

    expect($workspace->read('plan.md'))->toBe('ok');
});

it('refuses an owner it cannot address', function (): void {
    expect(fn () => PrismWorkspace::for(new stdClass))
        ->toThrow(WorkspaceFailed::class);

    try {
        PrismWorkspace::for(new stdClass);
    } catch (WorkspaceFailed $failed) {
        expect($failed->fault)->toBe(Fault::OwnerNotAddressable);
    }
});

it('refuses an escape at the workspace, not only at the guard', function (): void {
    $workspace = PrismWorkspace::for('agent-1');

    foreach (['../escaped.txt', '/etc/passwd', 'notes.txt:hidden', 'nul.log'] as $path) {
        expect(fn () => $workspace->write($path, 'x'))->toThrow(PathRefused::class);
        expect(fn () => $workspace->read($path))->toThrow(PathRefused::class);
        expect(fn () => $workspace->delete($path))->toThrow(PathRefused::class);
    }
});

it('guards both ends of a copy and a move', function (): void {
    $workspace = PrismWorkspace::for('agent-1');
    $workspace->write('source.txt', 'x');

    // A copy is two paths, and a guard applied to one of them is a guard
    // applied to none of them.
    expect(fn () => $workspace->copy('source.txt', '../escaped.txt'))->toThrow(PathRefused::class);
    expect(fn () => $workspace->move('source.txt', '../escaped.txt'))->toThrow(PathRefused::class);
    expect(fn () => $workspace->copy('../secret.txt', 'stolen.txt'))->toThrow(PathRefused::class);

    $workspace->copy('source.txt', 'archive/source.txt');

    expect($workspace->read('archive/source.txt'))->toBe('x');
});

it('reports a missing file as a fault rather than a refusal', function (): void {
    $workspace = PrismWorkspace::for('agent-1');

    try {
        $workspace->read('nothing-here.txt');
    } catch (WorkspaceFailed $failed) {
        // Faults and refusals are separate code spaces on purpose. A refusal is
        // a security event somebody pages on; a missing file is Tuesday.
        expect($failed->fault)->toBe(Fault::FileMissing);

        return;
    }

    throw new Exception('Expected a fault.');
});

it('streams a listing instead of materialising it', function (): void {
    $workspace = PrismWorkspace::for('agent-1');

    foreach (range(1, 50) as $index) {
        $workspace->write("bulk/file-{$index}.txt", (string) $index);
    }

    $listing = $workspace->list();

    expect($listing)->toBeInstanceOf(LazyCollection::class);

    // The regression this actually guards: someone "simplifying" list() into
    // LazyCollection::make($disk->allFiles()), which is a LazyCollection over
    // an array that was already built in full. The source has to be a closure.
    $source = (new ReflectionClass($listing))->getProperty('source');

    expect($source->getValue($listing))->toBeInstanceOf(Closure::class);

    expect($listing->take(3)->all())->toHaveCount(3)
        ->and($workspace->list()->filter(fn (WorkspaceEntry $entry): bool => $entry->isFile())->count())->toBe(50);
});

it('lists entries with their names and sizes', function (): void {
    $workspace = PrismWorkspace::for('agent-1');
    $workspace->write('reports/q1.md', '# Q1');

    $entries = $workspace->list()->keyBy(fn (WorkspaceEntry $entry): string => $entry->path);

    expect($entries->has('reports'))->toBeTrue()
        ->and($entries->get('reports')->isDirectory)->toBeTrue()
        ->and($entries->get('reports/q1.md')->isFile())->toBeTrue()
        ->and($entries->get('reports/q1.md')->size)->toBe(4)
        ->and($entries->get('reports/q1.md')->name())->toBe('q1.md');
});

it('empties itself without deleting itself', function (): void {
    $workspace = PrismWorkspace::for('agent-1');
    $workspace->write('a.txt', 'a')->write('sub/b.txt', 'b');

    $workspace->clear();

    expect($workspace->list()->count())->toBe(0)
        ->and(is_dir((string) $workspace->root()))->toBeTrue();
});

it('leaves authorization alone until the application asks for it', function (): void {
    // Off by default. An app that has defined no abilities gets a workspace
    // that works, rather than a queue worker where every write is denied
    // because there is no authenticated user to authorise.
    Gate::define('workspace.write', fn (): bool => false);

    PrismWorkspace::for('agent-1')->write('allowed.txt', 'x');

    expect(PrismWorkspace::for('agent-1')->read('allowed.txt'))->toBe('x');
});

it('asks the application Gate once turned on, and does not invent a permission system', function (): void {
    config()->set('prism-workspace.authorize', true);

    // The first parameter is nullable so the gate runs for a guest. A queue
    // worker has no authenticated user, and that is the context an agent
    // usually runs in.
    Gate::define('workspace.write', fn (?Authenticatable $user = null): bool => false);
    Gate::define('workspace.read', fn (?Authenticatable $user = null): bool => true);

    $workspace = PrismWorkspace::for('agent-1');

    expect(fn () => $workspace->write('denied.txt', 'x'))->toThrow(AuthorizationException::class);

    $workspace->disk()->put('seeded.txt', 'x');

    expect($workspace->read('seeded.txt'))->toBe('x');
});

it('never authorises a path it has not already guarded', function (): void {
    config()->set('prism-workspace.authorize', true);

    $seen = [];

    Gate::define('workspace.write', function (?Authenticatable $user, $workspace, $path) use (&$seen): bool {
        $seen[] = $path;

        return true;
    });

    $workspace = PrismWorkspace::for('agent-1');

    expect(fn () => $workspace->write('../escaped.txt', 'x'))->toThrow(PathRefused::class);

    // The refusal came first, so the policy was never handed a path that leaves
    // the workspace. A policy asked about `../escaped.txt` is a policy that
    // could say yes.
    expect($seen)->toBe([]);

    $workspace->write('./sub//report.md', 'x');

    expect($seen)->toBe(['sub/report.md']);
});

it('reads the config key it actually publishes', function (): void {
    // The merge landed under the published key, and nothing was left behind
    // under the unprefixed one.
    expect(config('prism-workspace.gate_prefix'))->toBe('workspace')
        ->and(config('workspace'))->toBeNull();

    // And the manager READS it. Without this line the rename could have been
    // half-done and every test would still pass: they all set the key they
    // expect, so a manager reading a different key would fall through to its
    // own defaults — `local` and `workspaces` — and behave identically.
    //
    // That is exactly how prism-harness shipped a config nobody exercised. The
    // fix there was a test that reads the SHIPPED configuration rather than one
    // the test wrote; this is that test.
    config()->set('prism-workspace.root', 'artifacts');

    app()->forgetInstance(WorkspaceManager::class);
    PrismWorkspace::clearResolvedInstances();

    expect(PrismWorkspace::for('agent-1')->root())->toContain('artifacts');
});

it('denies rather than runs when a gate callback was not written for a guest', function (): void {
    config()->set('prism-workspace.authorize', true);

    $ran = false;

    // The obvious signature, and the trap. Laravel only invokes a gate for an
    // unauthenticated user when the callback's FIRST parameter is explicitly
    // nullable; this one is not, so for a guest the callback never runs and the
    // check denies.
    Gate::define('workspace.write', function ($user, $workspace, $path) use (&$ran): bool {
        $ran = true;

        return true;
    });

    expect(fn () => PrismWorkspace::for('agent-1')->write('notes.md', 'x'))
        ->toThrow(AuthorizationException::class);

    expect($ran)->toBeFalse();

    // Pinned because the README and the Authorizer both cite it as the reason
    // authorization is off by default, and a claim about framework behaviour
    // sitting only in prose is how a plan gets mistaken for an implementation.
    // A queue worker is exactly this context: no authenticated user, an agent
    // that stops writing files, and nobody watching.
});
