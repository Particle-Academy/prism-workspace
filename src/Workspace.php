<?php

declare(strict_types=1);

namespace Prism\Workspace;

use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Support\LazyCollection;
use League\Flysystem\FileAttributes;
use League\Flysystem\StorageAttributes;
use Prism\Workspace\Exceptions\Fault;
use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Exceptions\WorkspaceFailed;
use Prism\Workspace\Path\LocalBoundary;
use Prism\Workspace\Path\PathGuard;
use Prism\Workspace\Security\CorpusRunner;
use Prism\Workspace\Support\Authorizer;

/**
 * A bounded place for an agent to keep its work.
 *
 * Underneath it is a Laravel `scoped` disk and nothing more exotic. That is the
 * design, not a shortcut: Laravel's `Storage` already gives scoped disks with
 * drivers for local, S3 and the rest, and reimplementing that would buy a second
 * set of filesystem bugs and no capability at all. What this class adds is an
 * agent-shaped API over it and a guard in front of every path.
 *
 * ## Every operation, same three steps
 *
 *   1. {@see PathGuard} — refuse the name, without touching the disk.
 *   2. {@see Authorizer} — ask the application's Gate, if it defined one.
 *   3. {@see LocalBoundary} — refuse where the name LEADS, which costs a
 *      syscall and so happens after the two checks that do not.
 *
 * The order matters in one direction in particular: nothing is ever authorised
 * before it is guarded, so a policy is never handed a path that has not already
 * been proven to stay inside.
 *
 * ## What it deliberately does not do
 *
 * There is no `run()`. Executing model-generated code is a remote-code-execution
 * surface by construction, and the isolation question — none, container, hosted
 * sandbox — has not been answered. A half-isolated sandbox is a more expensive
 * mistake than no sandbox, so the method is absent rather than present and
 * throwing: a method that exists is a shape the ecosystem has to live with.
 */
final class Workspace
{
    public function __construct(
        private readonly string $address,
        private readonly FilesystemAdapter $disk,
        private readonly PathGuard $guard,
        private readonly Authorizer $authorizer,
        private readonly ?LocalBoundary $boundary = null,
    ) {}

    /**
     * The directory this workspace lives in, relative to the configured root.
     */
    public function address(): string
    {
        return $this->address;
    }

    /**
     * The disk underneath, for the rare case that needs it.
     *
     * Unguarded by definition — anything reached through here has stepped
     * around the boundary this package exists to hold. It is here because a
     * package that leaves no way out gets forked, and a documented way out is
     * better than a fork.
     */
    public function disk(): FilesystemAdapter
    {
        return $this->disk;
    }

    /**
     * Run a path through the guard and get back the normalised form.
     *
     * @throws PathRefused
     */
    public function path(string $path): string
    {
        return $this->guard->guard($path);
    }

    public function exists(string $path): bool
    {
        return $this->disk->exists($this->admit($path, 'read'));
    }

    public function read(string $path): string
    {
        $contents = $this->disk->get($this->admit($path, 'read'));

        if ($contents === null) {
            throw WorkspaceFailed::make(Fault::FileMissing, "There is no [{$path}] in this workspace.");
        }

        return $contents;
    }

    /**
     * @return resource
     */
    public function readStream(string $path)
    {
        $stream = $this->disk->readStream($this->admit($path, 'read'));

        if (! is_resource($stream)) {
            throw WorkspaceFailed::make(Fault::FileMissing, "There is no [{$path}] in this workspace.");
        }

        return $stream;
    }

    public function write(string $path, string $contents): self
    {
        $guarded = $this->admit($path, 'write');

        if ($this->disk->put($guarded, $contents) === false) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not write [{$path}] to this workspace.");
        }

        return $this;
    }

    /**
     * @param  resource  $resource
     */
    public function writeStream(string $path, $resource): self
    {
        $guarded = $this->admit($path, 'write');

        if ($this->disk->writeStream($guarded, $resource) === false) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not write [{$path}] to this workspace.");
        }

        return $this;
    }

    public function append(string $path, string $contents): self
    {
        $guarded = $this->admit($path, 'write');

        if ($this->disk->append($guarded, $contents) === false) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not append to [{$path}] in this workspace.");
        }

        return $this;
    }

    /**
     * BOTH ends are guarded, which is the whole reason this is not a helper
     * around two calls: a copy is two paths, and a guard applied to one of them
     * is a guard applied to none of them.
     */
    public function copy(string $from, string $to): self
    {
        $source = $this->admit($from, 'read');
        $destination = $this->admit($to, 'write');

        if (! $this->disk->copy($source, $destination)) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not copy [{$from}] to [{$to}].");
        }

        return $this;
    }

    public function move(string $from, string $to): self
    {
        $source = $this->admit($from, 'write');
        $destination = $this->admit($to, 'write');

        if (! $this->disk->move($source, $destination)) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not move [{$from}] to [{$to}].");
        }

        return $this;
    }

    public function delete(string $path): self
    {
        $guarded = $this->admit($path, 'delete');

        if (! $this->disk->delete($guarded) && $this->disk->exists($guarded)) {
            throw WorkspaceFailed::make(Fault::DeleteFailed, "Could not delete [{$path}] from this workspace.");
        }

        return $this;
    }

    public function makeDirectory(string $path): self
    {
        if (! $this->disk->makeDirectory($this->admit($path, 'write'))) {
            throw WorkspaceFailed::make(Fault::WriteFailed, "Could not create the directory [{$path}].");
        }

        return $this;
    }

    public function deleteDirectory(string $path): self
    {
        if (! $this->disk->deleteDirectory($this->admit($path, 'delete'))) {
            throw WorkspaceFailed::make(Fault::DeleteFailed, "Could not delete the directory [{$path}].");
        }

        return $this;
    }

    public function size(string $path): int
    {
        $guarded = $this->admit($path, 'read');

        if (! $this->disk->exists($guarded)) {
            throw WorkspaceFailed::make(Fault::FileMissing, "There is no [{$path}] in this workspace.");
        }

        return $this->disk->size($guarded);
    }

    public function lastModified(string $path): int
    {
        $guarded = $this->admit($path, 'read');

        if (! $this->disk->exists($guarded)) {
            throw WorkspaceFailed::make(Fault::FileMissing, "There is no [{$path}] in this workspace.");
        }

        return $this->disk->lastModified($guarded);
    }

    /**
     * Everything in the workspace, streamed.
     *
     * A LazyCollection over Flysystem's own generator, so nothing is
     * materialised. An agent that has written ten thousand files should be able
     * to list them without the listing being the thing that runs the worker out
     * of memory — and `->take(5)` should cost five entries, not ten thousand.
     *
     * @return LazyCollection<int, WorkspaceEntry>
     */
    public function list(string $directory = '', bool $recursive = true): LazyCollection
    {
        $location = $directory === '' ? '' : $this->admit($directory, 'list');

        return LazyCollection::make(function () use ($location, $recursive): iterable {
            /** @var StorageAttributes $attributes */
            foreach ($this->disk->getDriver()->listContents($location, $recursive) as $attributes) {
                yield new WorkspaceEntry(
                    path: $attributes->path(),
                    isDirectory: $attributes->isDir(),
                    size: $attributes instanceof FileAttributes ? $attributes->fileSize() : null,
                    lastModified: $attributes->lastModified(),
                );
            }
        });
    }

    /**
     * Empty the workspace, keeping the workspace itself.
     */
    public function clear(): self
    {
        $this->authorizer->check('delete', $this);

        foreach ($this->disk->directories() as $directory) {
            $this->disk->deleteDirectory($directory);
        }

        $this->disk->delete($this->disk->files());

        return $this;
    }

    /**
     * The absolute directory, for local disks only — null for S3 and friends.
     *
     * Exists so {@see CorpusRunner} can sweep the
     * surrounding directories for anything an attempt managed to leave there.
     * Proving that nothing escaped is worth one method that admits where the
     * files are.
     */
    public function root(): ?string
    {
        $root = $this->disk->path('');

        return $root === '' ? null : rtrim($root, '/\\');
    }

    /**
     * Guard, authorise, then check where it leads. In that order, always.
     *
     * @throws PathRefused
     */
    private function admit(string $path, string $ability): string
    {
        $guarded = $this->guard->guard($path);

        $this->authorizer->check($ability, $this, $guarded);

        $this->boundary?->admit($guarded);

        return $guarded;
    }
}
