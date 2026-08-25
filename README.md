# Prism Workspace

A sandboxed place for an agent to keep its work — a scoped Laravel `Storage` disk with an
agent-shaped API over it, and a path guard that is the actual product.

```php
use Prism\Workspace\Facades\PrismWorkspace;

$workspace = PrismWorkspace::for($session);

$workspace->write('reports/q1.md', $content);
$workspace->read('reports/q1.md');
$workspace->list();                       // streamed, not materialised
```

> **Status: files only. Code execution is deferred, deliberately** — see
> [Still open](#still-open--raised-not-settled).

The model, the vocabulary and the cross-package decisions this package agrees with live in
[`prism-parity`](https://github.com/Particle-Academy/prism-parity):
[`docs/patterns/`](https://github.com/Particle-Academy/prism-parity/tree/main/docs/patterns)
and
[`docs/decisions/`](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions).
**This README links there and does not restate them.**

## The one thing it has to get right

A path escaping its workspace is the failure that matters. Everything else here is
convenience around that.

Which sets a harder standard than "has a sandbox": **the boundary holds, and you can watch it
hold.**

### The corpus ships with the package

134 adversarial paths across twelve hazard classes, in `Prism\Workspace\Security\EscapeCorpus`
— not in `/tests`, and `/tests` is not `export-ignore`d either. Point it at a workspace built
from **your** disk configuration:

```php
use Prism\Workspace\Security\CorpusRunner;

$report = (new CorpusRunner)->against(PrismWorkspace::for($session));

if (! $report->passed()) {
    throw new RuntimeException($report->summary());
}
```

It is safe against a live workspace: a passing run writes nothing, because every attempt is
refused. Two checks run, not one — every attempt is refused with the code the corpus names,
**and** the directories around the workspace are then swept for the run's marker. The second
catches the mistake the first cannot: a guard that refuses everything correctly, in front of a
root that was assembled wrongly.

A security property is only true of the configuration it was measured on. Ours is measured in
CI. Yours is yours to measure.

### Every case is proven to escape an unguarded workspace first

A guard nobody has watched fail is a hypothesis. Each corpus case records what an *unguarded*
resolver does with it — per platform — and the suite executes that claim as well as the
refusal. Without it, a wall of green refusals would only prove the guard agrees with itself.

Both platform models run on **both** platforms, and CI runs on `windows-latest` as well as
`ubuntu-latest`, because 24 cases are classified differently on the two:

| | Windows | Linux |
|---|---|---|
| `..\secret.txt` | escapes | a filename |
| `C:\Windows\System32\config\SAM` | escapes | a filename |
| `\\server\share\secret.txt` | escapes | a filename |
| `/etc/passwd` | escapes | escapes |

The tempting read is that Linux is safe from the Windows spellings. It is the opposite: on
Linux those are legal filenames, so an unguarded workspace **stores** them — and the directory
is synced, shared or mounted, a Windows worker opens it, and now the file is an escape.

## What Laravel already does, and what this adds

Measured, not asserted, and pinned in `tests/Integration/BareDiskBaselineTest.php` so a
Flysystem release that moves it fails a build rather than leaving this section quietly wrong.

Bare `league/flysystem` 3.35 local adapter, 134 attempts, Windows 11 / PHP 8.4:

| | |
|---|---|
| **46 refused by Flysystem** | 22 traversal, 24 corrupted-path (Unicode category C; invalid UTF-8 only since 3.35). Portable and genuinely good. |
| **24 refused by the operating system** | Trailing dots, edge spaces, over-long names. Platform-dependent — most are legal on Linux. |
| **64 accepted** | Device names, alternate data streams, 8.3 aliases, every percent-encoding, separator homoglyphs, `~/.ssh/id_rsa`, and every absolute path. |

Some of that coverage is also **version-dependent**. Invalid UTF-8 — the bytes `C3 28` — is
accepted by Flysystem 3.25 and refused by 3.35, because `preg_match` with `/u` returns `false`
rather than `0` on a subject that is not valid UTF-8, so the older check never fired. Which is
the strongest argument there is for a package checking that class itself, and the reason the
guard validates encoding *before* it runs a single `/u` pattern.

So this package is **not** what stands between an agent and `../../etc/passwd` on a Laravel
disk. Flysystem's own normaliser already refuses that, and saying otherwise would be a
marketing claim in a security package. What it adds:

- the 64 the framework accepts, refused
- an absolute path **refused** rather than silently relocated. `put('/etc/passwd')` on a bare
  disk drops the leading slash and writes `etc/passwd` inside the root: contained, wrong, and
  no error anywhere. A successful call that did something else is worse than an exception.
- a **stable code** on every refusal instead of a message. `path_traverses_outside_workspace`
  is something you can alert on; a substring is something that gets reworded in a patch
  release.
- the same answer on both platforms for the same input
- the symlink boundary, which no path guard can provide

## The boundary, in two halves

`PathGuard` is a pure function from a string to a safer string. **Not one stat, not one
realpath** — asserted by a test that tokenises the source and fails if a filesystem call
appears. It runs on every operation, so it does not get to ask the disk a question about a
string.

`LocalBoundary` handles the escape a string cannot express. `reports/out.txt` is a flawless
relative path right up until `reports` is a link to `/etc`, so that check costs a syscall —
one `realpath` for a path that exists, two for a file about to be created, and the walk
upwards stops at the workspace root. Local disks only; there are no symlinks in S3.

Splitting them is what lets the first half be held to the no-syscall rule at all.

### It refuses shapes, not dangers

`..` is **refused, never resolved.** `docs/../report.md` lands inside the workspace, is
completely safe, and is refused anyway.

Resolving `..` correctly means being right on every input forever, and the pop-past-the-root
off-by-one is the most-repeated path bug in the field. Refusing the shape means being right
once. The same instinct runs through the rest: refuse a colon rather than decide whether this
one is a drive or a stream; refuse a leading `~` rather than guess which downstream consumer
expands it; fold backslashes to separators everywhere rather than let one string mean two
things.

Where that costs something, the cost is a corpus case rather than a surprise:

| Refused | Cost | Case |
|---|---|---|
| `docs/../report.md` | Safe, resolves inside | `str-0001` |
| `draft~1.txt` | A reasonable filename that is exactly the 8.3 alias shape | `str-0003` |
| `..cache/notes.txt` | A directory that merely starts with two dots | `str-0004` |
| `a\b.txt` on Linux | A backslash is always a separator, so this becomes `a/b.txt` | — |

### Refusal codes

Codes are the contract; prose is not — [decision
0004](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions). It matters
more here than for the ports: a refusal from this package is a security event.

```php
try {
    $workspace->write($pathFromTheModel, $content);
} catch (PathRefused $refused) {
    Log::warning('agent tried to leave its workspace', [
        'code' => $refused->refusal->value,   // path_traverses_outside_workspace
        'path' => $refused->path,
    ]);
}
```

`Prism\Workspace\Exceptions\Refusal` is the full taxonomy. `Fault` is a separate code space for
failures that are not about the path — a missing file is operations, not a security event, and
an alert that fires on both gets muted.

**Order of checks is contract**, not an implementation detail. `/../secret.txt` is absolute
*and* traversing and gets exactly one code; the corpus pins which.

## Addressing

A workspace is addressed rather than owned — the same reason the harness's threads are
addressed by participant and scope. Four ways in, tried in order:

1. `Prism\Workspace\Contracts\WorkspaceOwner` — the explicit contract.
2. Any object with a `key(): string` method, which is what a `prism-harness` `Session` already
   is.
3. An Eloquent model — morph class and key, hashed the way the harness hashes a session
   address.
4. A string, for a job id.

### On the duck typing in step 2

**It is the right answer here, not a shortcut, and the alternatives were weighed and rejected
rather than overlooked.**

A harness `Session` is the intended address for a workspace, and the obvious move is a shared
interface. Every way of having one is worse:

| | |
|---|---|
| The harness implements a workspace contract | Inverts the dependency. Sessions would wait on releases of the thing that stores their files. |
| The contract lives in `prism` core | Barred. Core is a provider API shuttle and this does not touch the wire. |
| A shared contracts package | Rejected by [decision 0008](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions): a common parent makes every package in the ecosystem wait on a release of the parent. |

So it is a method name, matched at the call site, and it works today with no release of either
package and no `require` in either direction. The coupling is real — renaming `Session::key()`
would silently give every workspace a new address — and it is paid deliberately, which is a
different thing from not having noticed it. Implement `WorkspaceOwner` when you want the
coupling to be explicit and checked.

## The on-disk layout is a stable contract

```
<disk>/<root>/<slug>-<sha256:16>/…
```

Default: `storage/app/workspaces/agent-1-9f86d081884c7d65/…`

**Treat this as published and stable. Changing it is a breaking change**, and it will be
handled like one.

That is a promise worth making explicitly, because anything reading these directories from
outside PHP — a backup job, a retention sweep, an operator with `ls`, a sidecar in another
language — depends on the layout whether or not it is written down. An undocumented layout that
consumers depend on anyway is the worst of both: no freedom to change it, and no warning when
it changes.

The address is slugged **and** hashed. The readable half is for whoever opens the directory;
the hash is what makes it correct:

- a harness session key is `session:<hash>:<id>:<scope>`, and a colon is illegal in a Windows
  filename, so the raw key cannot be a directory name
- two keys differing only in case are different owners and the *same directory* on Windows and
  macOS, and the hash is what stops them sharing a workspace
- slugging is lossy, so two distinct keys can slug identically; the hash is taken over the raw
  key, before any of that

The result is then run back through the guard, because a generated path segment is still a path
segment.

## Permissions are Laravel Gates

*May this agent do this here* is an authorization question, and Laravel has an answer to those.
So there is no permission model in this package, only a call into yours.

**This is where that convention was made, not where it was inherited.** `prism-harness` has a
row in its README's concepts table mapping permissions onto Gates and Policies, and it was
tempting — including for me — to cite that as settled. It is not: the harness's own status line
says permissions are "decisions, not code yet", and there is no `Gate`, `Policy` or `authorize`
anywhere in its `src/`. A plan written next to shipped code still reads like shipped code.

The decision stands on its own merits, which is why it survived losing its provenance. If you
came here looking for the harness implementation to match, there isn't one to match yet — this
is the reference.

```php
// config/prism-workspace.php
'authorize' => true,
```

```php
Gate::define('workspace.write', fn (?User $user, Workspace $workspace, ?string $path) => ...);
```

`workspace.read`, `.write`, `.delete`, `.list`, each passed the workspace and the **guarded**
path — nothing is authorised before it is guarded, so a policy is never asked about a path that
leaves the workspace.

### Off by default, and this part is the precedent

The sandbox is the boundary. The Gate is your policy **on top of** the boundary, and it is
opt-in because the failure modes are not symmetric.

An application that never defines the abilities gets a workspace that works. A default-on check
denies **every operation in a queue worker**, where there is no authenticated user — an agent
that silently stops writing files, in the context where nobody is watching. One of those is a
missing feature; the other is a production incident that looks like the model got lazy.

Guest access is the trap underneath it. Laravel only runs a gate for an unauthenticated user
when the callback's first parameter is explicitly nullable, so a callback written
`fn ($user, $workspace, $path)` denies silently rather than running. Any package turning this
on by default would be shipping that denial to every consumer who wrote the obvious signature.

`prism-harness` did ship a default that assumed infrastructure the installing app had not
claimed to have — a Redis it had no way to know was there — and had to reverse it. That one is
real, it is in the commit log, and it is the reason this is off rather than on. Once is a
mistake; twice would be a convention.

Any sibling package adding an authorization check should start here: **Gates, ability names it
owns, and off until the application opts in.**

## Listing streams

`list()` returns a `LazyCollection` over Flysystem's own generator. An agent that has written
ten thousand files should be able to list them without the listing being what runs the worker
out of memory, and `->take(5)` should cost five entries rather than ten thousand.

## Installation

```bash
composer require particle-academy/prism-workspace
```

Works on install with nothing to configure: the default disk is `local` and workspaces land in
`storage/app/workspaces`. Publish the config to change any of it:

```bash
php artisan vendor:publish --tag=prism-workspace-config
```

The file is `config/prism-workspace.php`, prefixed, because a published config file is a
filename in *your* config directory and `workspace.php` is a name an application is entirely
likely to want for itself. The gate prefix is a separate namespace and stays `workspace` — see
above.

No dependency on `particle-academy/prism` — nothing here touches the wire, so requiring the
provider shuttle would cost every installer a package that buys them nothing.
`prism-harness` is a `suggest` for the same reason.

## Still open — raised, not settled

Escalations, not TODOs. They bind other packages, so they are not this package's to answer
alone — [decision
0008](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions).

**Is code execution in scope, and if so how is it isolated?** There is no `run()`, and the
method is *absent* rather than present-and-throwing, because a method that exists is a shape
the ecosystem has to live with. Running model-generated code is a remote-code-execution
surface by construction; a half-isolated sandbox is a more expensive mistake than no sandbox.
A scoped filesystem is genuinely useful on its own, and this package can hold its boundary
today in a way it could not if it also spawned processes.

**What is a skill file?** Prompt fragment, tool definition, or executable are three different
packages with three different threat models — the third is code execution wearing a friendlier
name. Until the phrase means one of them concretely, nothing is built.

**Lifetime.** A workspace outlives its session today and nothing deletes it. `clear()` exists;
a policy does not. Unbounded artifacts accumulating on a customer's disk with no cleanup path
is a support ticket with a delay fuse.

## What it will never do

**No UI.** No file browser. Fancy owns screens; Prism owns capability.

## License

MIT.
