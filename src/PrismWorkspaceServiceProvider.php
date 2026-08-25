<?php

declare(strict_types=1);

namespace Prism\Workspace;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Support\ServiceProvider;

final class PrismWorkspaceServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/workspace.php', 'workspace');

        // The manager is a singleton; the workspaces it hands out are cached
        // per address for the request and no longer. A workspace held across
        // requests is a scoped disk built from configuration that may have
        // changed underneath it.
        $this->app->singleton(WorkspaceManager::class, fn ($app): WorkspaceManager => new WorkspaceManager(
            filesystem: $app->make(FilesystemManager::class),
            gate: $app->make(Gate::class),
            config: $app->make(Repository::class),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/workspace.php' => config_path('workspace.php'),
            ], 'workspace-config');
        }
    }
}
