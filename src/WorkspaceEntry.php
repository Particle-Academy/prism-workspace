<?php

declare(strict_types=1);

namespace Prism\Workspace;

/**
 * One thing in a workspace, as a listing sees it.
 *
 * Deliberately thin. It carries what a directory listing already knows and
 * nothing that would need a second call to answer — a listing of ten thousand
 * files must not become ten thousand stats.
 */
final readonly class WorkspaceEntry
{
    public function __construct(
        /** Relative to the workspace root, always with forward slashes. */
        public string $path,
        public bool $isDirectory,
        /** Null for directories, and for adapters that do not report it in a listing. */
        public ?int $size = null,
        public ?int $lastModified = null,
    ) {}

    public function isFile(): bool
    {
        return ! $this->isDirectory;
    }

    public function name(): string
    {
        $slash = strrpos($this->path, '/');

        return $slash === false ? $this->path : substr($this->path, $slash + 1);
    }
}
