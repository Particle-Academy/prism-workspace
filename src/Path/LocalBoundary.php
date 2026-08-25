<?php

declare(strict_types=1);

namespace Prism\Workspace\Path;

use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Exceptions\Refusal;

/**
 * The half of the boundary that a string cannot answer.
 *
 * {@see PathGuard} proves a NAME stays inside the workspace. It cannot prove
 * where that name LEADS, because a symlink is filesystem state: `reports/out`
 * is a flawless relative path right up until `reports` is a link to `/etc`.
 * Every check here therefore costs a syscall, which is exactly why it is not in
 * the guard.
 *
 * Local disks only. There are no symlinks in S3, and no MAX_PATH either.
 *
 * ## The cost, since it is on every operation
 *
 * One `realpath` for a path that exists, two for a file about to be created —
 * because a new file has no realpath and the deepest EXISTING ancestor is what
 * has to be checked. The walk upwards stops at the workspace root and so is
 * bounded by depth, not by the size of the workspace.
 *
 * ## Why Laravel's own link handling is not enough on its own
 *
 * Flysystem's local adapter defaults to DISALLOW_LINKS and throws when it meets
 * one, which is genuinely good. But that default belongs to the CONSUMER's disk
 * configuration — a `'links' => 'skip'` in their `filesystems.php` turns it off,
 * and this package would then be relying on a setting it does not own for the
 * one property it exists to provide. So the check is made here as well, and the
 * corpus runner is shipped so a consumer can prove it on their own config
 * rather than on ours.
 */
final class LocalBoundary
{
    public function __construct(
        /** The workspace directory, absolute. */
        private readonly string $root,
        /**
         * The Win32 limit for a full path, or null where long paths are enabled.
         *
         * This is why the guard's own length budget is generous: how much room
         * a relative path has left depends on where the disk root is, which is
         * a question about the filesystem and not about the string.
         */
        private readonly ?int $windowsMaxPath = 259,
    ) {}

    /**
     * @throws PathRefused
     */
    public function admit(string $relative): void
    {
        $target = $this->absolute($relative);

        if (PHP_OS_FAMILY === 'Windows' && $this->windowsMaxPath !== null && strlen($target) > $this->windowsMaxPath) {
            throw PathRefused::make(Refusal::TooLong, $relative, sprintf(
                'the full path would be %d characters and Windows stops at %d unless long paths are enabled',
                strlen($target),
                $this->windowsMaxPath,
            ));
        }

        $root = realpath($this->root);

        if ($root === false) {
            // The workspace directory does not exist yet, so there is nothing
            // to be linked through. It is created on first write, and every
            // write after that is checked.
            return;
        }

        $resolved = $this->deepestExisting($target);

        if ($resolved !== null && ! $this->within($root, $resolved)) {
            throw PathRefused::make(Refusal::EscapesViaLink, $relative, sprintf(
                'it resolves to [%s], which is outside the workspace — a directory on the way is a link',
                $resolved,
            ));
        }
    }

    private function absolute(string $relative): string
    {
        return rtrim($this->root, '/\\').DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $relative);
    }

    /**
     * `realpath` of the target, or of the nearest ancestor that exists.
     *
     * A file about to be created has no realpath of its own, and the escape it
     * would suffer belongs to its parent anyway: if `reports` is a link out,
     * then so is everything written beneath it.
     */
    private function deepestExisting(string $target): ?string
    {
        $candidate = $target;

        for ($depth = 0; $depth < 64; $depth++) {
            $resolved = realpath($candidate);

            if ($resolved !== false) {
                return $resolved;
            }

            $parent = dirname($candidate);

            if ($parent === $candidate || strlen($parent) < strlen($this->root)) {
                return null;
            }

            $candidate = $parent;
        }

        return null;
    }

    private function within(string $root, string $candidate): bool
    {
        if (PHP_OS_FAMILY === 'Windows') {
            // NTFS folds case, so a containment check that does not fold case
            // is a containment check with a hole in it.
            $root = mb_strtolower($root, 'UTF-8');
            $candidate = mb_strtolower($candidate, 'UTF-8');
        }

        return $candidate === $root
            || str_starts_with($candidate, rtrim($root, '/\\').DIRECTORY_SEPARATOR);
    }
}
