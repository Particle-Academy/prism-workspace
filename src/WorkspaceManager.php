<?php

declare(strict_types=1);

namespace Prism\Workspace;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Filesystem\FilesystemManager;
use Prism\Workspace\Path\LocalBoundary;
use Prism\Workspace\Path\PathGuard;
use Prism\Workspace\Support\Authorizer;
use Prism\Workspace\Support\WorkspaceAddress;
use RuntimeException;

/**
 * Resolves the workspace an owner is addressed by.
 *
 *     $workspace = PrismWorkspace::for($session);
 *
 * A workspace is a `scoped` Laravel disk — the driver Laravel already ships for
 * exactly this — pinned to `<root>/<address>` on whichever disk the application
 * configured. Local, S3, anything with a Flysystem adapter; the boundary is the
 * same because the guard in front of it is the same.
 *
 * Resolved per address and cached for the request, not held across requests.
 * Same reasoning as the harness's sessions: nothing survives a Laravel request,
 * so anything that looks like it does is a stale copy waiting to happen.
 */
final class WorkspaceManager
{
    /** @var array<string, Workspace> */
    private array $resolved = [];

    public function __construct(
        private readonly FilesystemManager $filesystem,
        private readonly Gate $gate,
        private readonly Repository $config,
    ) {}

    /**
     * @param  mixed  $owner  A harness Session, a WorkspaceOwner, an Eloquent model, or a stable string.
     */
    public function for(mixed $owner): Workspace
    {
        $address = WorkspaceAddress::for($owner, $this->guard());

        return $this->resolved[$address] ??= $this->build($address);
    }

    public function guard(): PathGuard
    {
        return new PathGuard(
            maxPathLength: (int) $this->setting('max_path_length', 1024),
            maxSegmentLength: (int) $this->setting('max_segment_length', 255),
        );
    }

    private function build(string $address): Workspace
    {
        $disk = (string) $this->setting('disk', 'local');
        $root = trim((string) $this->setting('root', 'workspaces'), '/');

        $adapter = $this->filesystem->build([
            'driver' => 'scoped',
            'disk' => $disk,
            'prefix' => $root === '' ? $address : "{$root}/{$address}",
        ]);

        if (! $adapter instanceof FilesystemAdapter) {
            throw new RuntimeException('The configured workspace disk did not resolve to a Laravel filesystem adapter.');
        }

        return new Workspace(
            address: $address,
            disk: $adapter,
            guard: $this->guard(),
            authorizer: new Authorizer(
                gate: $this->gate,
                enabled: (bool) $this->setting('authorize', false),
                prefix: (string) $this->setting('gate_prefix', 'workspace'),
            ),
            boundary: $this->boundaryFor($disk, $adapter),
        );
    }

    /**
     * Only local disks get a link boundary, because only local disks have
     * links — or a MAX_PATH. Paying a `realpath` per operation against S3 would
     * be a syscall spent proving something that cannot happen there.
     */
    private function boundaryFor(string $disk, FilesystemAdapter $adapter): ?LocalBoundary
    {
        if ($this->config->get("filesystems.disks.{$disk}.driver") !== 'local') {
            return null;
        }

        $maxPath = $this->setting('windows_max_path', 259);

        return new LocalBoundary(
            root: rtrim($adapter->path(''), '/\\'),
            windowsMaxPath: $maxPath === null ? null : (int) $maxPath,
        );
    }

    private function setting(string $key, mixed $default): mixed
    {
        return $this->config->get("workspace.{$key}", $default);
    }
}
