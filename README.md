# Prism Workspace

A sandboxed place for an agent to keep its work — a scoped Laravel `Storage` disk with an
agent-shaped API over it, and a path guard that is the actual product.

> **Status: scaffold. No implementation yet.** This first commit exists so the design has
> somewhere to live before code does, and so the first real commits have something to answer
> to.

The model, the vocabulary and the cross-package decisions this package is built to agree with
live in [`prism-parity`](https://github.com/Particle-Academy/prism-parity) —
[`docs/patterns/`](https://github.com/Particle-Academy/prism-parity/tree/main/docs/patterns)
and
[`docs/decisions/`](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions).
**This README links there and does not restate them.** Restated documentation drifts exactly
like restated code, and nothing tests prose.

## What it is for

Agents that do work produce artifacts and need somewhere to put them. A coding assistant
writes files. A research agent saves a report. That is what this is — bounded, so an agent
cannot reach outside it.

## The one thing it has to get right

**A path escaping its workspace is the failure that matters. Everything else here is
convenience around that.**

Which sets the standard for the package: not "has a filesystem API" but "the boundary holds,
and you can watch it hold." Two consequences that shape every decision below.

**The escape corpus is written first and watched failing.** A guard nobody has seen fail is a
hypothesis, not a guard. Every adversarial case is proven to escape an *unguarded* resolver
before the guard exists to stop it, and that proof stays in the suite permanently rather than
being a thing that happened once on someone's laptop.

**The corpus ships in the package.** `/tests` is deliberately not `export-ignore`d, unlike
every sibling directory. A security boundary a consumer cannot independently verify against
*their own* disk configuration is a claim; one that ships its own adversarial suite is
evidence.

## Decisions taken before any code

| Question | Decision |
|---|---|
| Does it implement a filesystem? | **No.** A workspace is a `scoped` Laravel disk. Laravel already sandboxes; rebuilding it buys a second set of bugs and no capability. |
| What addresses a workspace? | A **session**. `prism-harness` owns sessions, the same way it owns threads — this package is addressed by identity rather than defining its own. |
| How are permissions expressed? | **Laravel Gates.** The harness already settled that "may this tool run" is an authorization question; a parallel permission system here would be a second answer to a question with one. |
| Does it depend on `prism`? | **No.** Nothing here touches the wire, so requiring the provider shuttle would be a dependency that buys the installer nothing. `prism-harness` is a `suggest`, not a `require`. |
| Does it change `prism` core? | **No.** Core is a provider API shuttle. Anything this package wants from it gets filed and worked around. |

## Still open — raised, not settled

These are escalations, not TODOs. They bind other packages, so they are not this package's to
answer alone — see
[decision 0008](https://github.com/Particle-Academy/prism-parity/tree/main/docs/decisions).

- **Is code execution in scope, and if so how is it isolated?** Running model-generated code
  is a remote-code-execution surface by construction. The current recommendation is *files
  only, execution deferred*: a scoped filesystem is genuinely useful alone, and a
  half-isolated sandbox is a more expensive mistake than no sandbox.
- **What is a skill file?** Prompt fragment, tool definition, or executable are three
  different packages. Until the phrase means one of them concretely, nothing gets built.
- **Lifetime.** Does a workspace outlive its session, and who deletes it? Unbounded artifacts
  accumulating on a customer's disk with no cleanup path is a support ticket with a delay
  fuse.

## What it will never do

**No UI.** No file browser. Fancy owns screens; Prism owns capability.
