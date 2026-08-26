# AGENTS.md — particle-academy/prism-workspace

A sandboxed place for an agent to keep its work: a scoped Laravel `Storage` disk
with an agent-shaped API over it, and a path guard that is the actual product.

> **Read [the shared guide](https://github.com/Particle-Academy/prism-parity/blob/main/docs/AGENTS.md)
> first** — the boundary, the gates, the binding decisions, the review skills.
> This file is only what is true of *this* repository.

## The guard is the package. Everything else is convenience.

A path escaping its workspace is the failure that matters. Treat any change
under `src/Path/` or `src/Security/` as a security change, and run
`security-review` over it before pushing — not as ceremony, but because the
suite passing is exactly what a broken guard looks like from here.

The standard is harder than "has a sandbox": **the boundary holds, and you can
watch it hold.**

## Three properties that are easy to erode and expensive to restore

**The corpus ships in `src/`, not `tests/`.** 134 adversarial paths across
twelve hazard classes live in `Prism\Workspace\Security\EscapeCorpus`, and
`tests/` is deliberately *not* `export-ignore`d. Consumers must be able to run
the corpus against **their** disk configuration, because a security property is
only true of the configuration it was measured on. Moving the corpus into
`tests/` for tidiness removes that, and it will look like a cleanup in the diff.

**Every case proves it escapes an *unguarded* workspace first.** A guard nobody
has watched fail is a hypothesis. Each case records what a bare resolver does
with it, per platform, and the suite executes that claim alongside the refusal.
Delete that half and a wall of green refusals only proves the guard agrees with
itself.

**Two checks per run, not one.** Every attempt must be refused with the code the
corpus names, **and** the directories around the workspace are then swept for
the run's marker. The second catches what the first cannot: a guard that refuses
everything correctly, in front of a root that was assembled wrongly.

## Both platform models run on both platforms. This is not redundancy.

CI runs `windows-latest` as well as `ubuntu-latest` because 24 cases are
classified differently on the two, and the tempting read is the wrong way round.

On Linux, `..\secret.txt` and `C:\Windows\…\SAM` are **legal filenames**, so an
unguarded workspace *stores* them. Then the directory is synced, shared or
mounted, a Windows worker opens it, and the stored filename is an escape. Linux
is not safe from the Windows spellings; it is where they get written.

Never drop a platform from the matrix to make CI faster.

## Claims in the README are measured, and pinned

The Flysystem baseline table — 46 refused by Flysystem, 24 by the OS, 64
accepted — is measured, not asserted, and pinned in
`tests/Integration/BareDiskBaselineTest.php` so a Flysystem release that moves
it fails a build rather than leaving the README quietly wrong.

If that test starts failing, **the README changes with the fix.** Adjusting the
test to match new behaviour and leaving the prose is how a security package ends
up making a marketing claim.

Note the version sensitivity that test exists to catch: invalid UTF-8 (`C3 28`)
is accepted by Flysystem 3.25 and refused by 3.35, because `preg_match` with
`/u` returns `false` rather than `0` on a subject that is not valid UTF-8, so
the older check never fired. That is why the guard **validates encoding before
it runs a single `/u` pattern**. Do not reorder those.

## Honesty about scope is part of the design

This package is **not** what stands between an agent and `../../etc/passwd` —
Flysystem's own normaliser already refuses that, and claiming otherwise would be
a marketing claim in a security package. What it adds is the 64 the framework
accepts, an absolute path refused rather than silently relocated, a stable
refusal **code** rather than a message, the same answer on both platforms, and
the symlink boundary.

Keep refusal codes stable. `path_traverses_outside_workspace` is something a
consumer can alert on; a message substring is something that gets reworded in a
patch release and breaks their alert silently.

## Deferred on purpose

**Code execution is not here, deliberately** — see *Still open* in the README.
Adding it is an ecosystem decision, not a feature branch.

## Gates

```sh
composer test && composer types && composer format
```

CI runs `tests`, `phpstan`, `formatting`, `require-checker`, on both platforms.
`particle-academy/prism-harness` is a **suggest**, not a require — the workspace
is useful without sessions.
