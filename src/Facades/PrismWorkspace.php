<?php

declare(strict_types=1);

namespace Prism\Workspace\Facades;

use Illuminate\Support\Facades\Facade;
use Prism\Workspace\Path\PathGuard;
use Prism\Workspace\Workspace;
use Prism\Workspace\WorkspaceManager;

/**
 * @method static Workspace for(mixed $owner)
 * @method static PathGuard guard()
 *
 * @see WorkspaceManager
 */
final class PrismWorkspace extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return WorkspaceManager::class;
    }
}
