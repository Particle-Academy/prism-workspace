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
 * `prism-harness` already settled that tool permissions are Gates and Policies,
 * on the grounds that *may this run* is an authorization question and Laravel
 * has an answer to those. A workspace is downstream of that decision rather
 * than a place to re-open it, so there is no permission model here — only a
 * call into the application's.
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
 * That is the same shape as the harness's Redis default, which was broken on
 * install for any app without Redis and had to be reversed. Once is a mistake;
 * twice would be a convention.
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
