<?php

declare(strict_types=1);

namespace Prism\Workspace;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

final class PrismWorkspaceServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/workspace.php', 'workspace');

        // The manager is a singleton; the workspaces it hands out are cached
        // per address for the request and no longer. A workspace held across
        // requests is a scoped disk built from configuration that may have
        // changed underneath it.
        $this->app->singleton(WorkspaceManager::class, function ($app): WorkspaceManager {
            // Resolved through the `filesystem` alias rather than by class
            // name. `make(FilesystemManager::class)` would autowire a SECOND
            // manager — one that has never seen a driver registered with
            // Storage::extend(), so an application with a custom disk would
            // find that its workspaces quietly used a different filesystem
            // stack from the rest of the app.
            $filesystem = $app->make('filesystem');

            if (! $filesystem instanceof FilesystemManager) {
                throw new RuntimeException('The [filesystem] binding is not a Laravel filesystem manager, so a scoped workspace disk cannot be built from it.');
            }

            return new WorkspaceManager(
                filesystem: $filesystem,
                gate: $app->make(Gate::class),
                config: $app->make(Repository::class),
            );
        });
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
