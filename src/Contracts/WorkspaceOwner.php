<?php

declare(strict_types=1);

namespace Prism\Workspace\Contracts;

use Prism\Workspace\Support\WorkspaceAddress;

/**
 * Something a workspace can belong to.
 *
 * A workspace is ADDRESSED rather than owned: it does not define an identity of
 * its own, for the same reason `prism-memory` does not own the conversation and
 * the harness's threads are addressed by participant and scope. Identity lives
 * where identity lives, and this package resolves a directory from it.
 *
 * Implementing this is the explicit way in. It is not the only one — a harness
 * `Session`, a plain Eloquent model and a string all resolve without it, so
 * that `prism-harness` does not have to ship a release to be usable here and an
 * application scoping a workspace to a job id does not have to write a class.
 * See {@see WorkspaceAddress} for the order those are
 * tried in.
 */
interface WorkspaceOwner
{
    /**
     * A stable string that identifies this owner.
     *
     * Stable is the whole requirement, and it is a stronger one than it looks:
     * a fresh worker resolving the same owner has to land on the SAME
     * workspace, or the artifacts of the run before it are simply gone. Do not
     * derive this from anything that changes between requests.
     */
    public function workspaceKey(): string;
}
