<?php

declare(strict_types=1);

namespace Prism\Workspace\Support;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Access\Gate;
use Prism\Workspace\Workspace;

/**
 * "May this agent do this here?" — asked of Laravel, not of a system this
 * package invented.
 *
 * *May this agent do this here* is an authorization question, and Laravel has
 * an answer to those. So there is no permission model here — only a call into
 * the application's.
 *
 * ## Provenance, because it was misattributed once already
 *
 * This package is where that convention was MADE. It was written here as
 * following a decision `prism-harness` had already taken, and that was wrong:
 * the harness has a row in its README's concepts table mapping permissions onto
 * Gates and Policies, but its own status line calls permissions "decisions, not
 * code yet" and there is no Gate, Policy or authorize anywhere in its `src/`.
 *
 * The claim survived because a plan written next to shipped code reads exactly
 * like shipped code. Corrected here rather than quietly, because the next agent
 * to read "per the harness's decision" goes looking for an implementation that
 * is not there.
 *
 * The design was right for the reason given even though the citation was not,
 * which is the only reason nothing had to be rebuilt.
 *
 * ## Off by default, and that is not an oversight
 *
 * The sandbox is the boundary. The Gate is the application's policy ON TOP of
 * the boundary, and it is opt-in because the failure modes are not symmetric:
 * an app that never defines the abilities gets a workspace that works, while a
 * default-on check would deny every operation in a queue worker where there is
 * no authenticated user — an agent that silently stops writing files, in the
 * context where nobody is watching.
 *
 * Underneath that sits a trap worth naming: Laravel only runs a gate for an
 * unauthenticated user when the callback's first parameter is explicitly
 * nullable. A callback written `fn ($user, $workspace, $path)` does not run at
 * all for a guest — it denies. Default-on would ship that silent denial to
 * every consumer who wrote the obvious signature.
 *
 * That is the same shape as the harness's Redis default, which WAS shipped and
 * WAS reversed — that one is in the commit log rather than in a table. Once is
 * a mistake; twice would be a convention.
 */
final class Authorizer
{
    public function __construct(
        private readonly Gate $gate,
        private readonly bool $enabled,
        private readonly string $prefix,
    ) {}

    /**
     * @throws AuthorizationException
     */
    public function check(string $ability, Workspace $workspace, ?string $path = null): void
    {
        if (! $this->enabled) {
            return;
        }

        $this->gate->authorize("{$this->prefix}.{$ability}", [$workspace, $path]);
    }
}
