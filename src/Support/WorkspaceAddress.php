<?php

declare(strict_types=1);

namespace Prism\Workspace\Support;

use Illuminate\Database\Eloquent\Model;
use Prism\Workspace\Contracts\WorkspaceOwner;
use Prism\Workspace\Exceptions\Fault;
use Prism\Workspace\Exceptions\WorkspaceFailed;
use Prism\Workspace\Path\PathGuard;

/**
 * Turns an owner into one directory name.
 *
 * Four ways in, tried in this order:
 *
 *  1. {@see WorkspaceOwner} — the explicit contract.
 *  2. Any object with a `key(): string` method. This is how a `prism-harness`
 *     Session works, and it is the RIGHT answer rather than a shortcut —
 *     ratified, after the three alternatives were weighed and each was worse.
 *     The harness implementing a workspace contract inverts the dependency;
 *     a contract in `prism` core is barred by the boundary, since none of this
 *     touches the wire; and a shared contracts package is rejected outright by
 *     decision 0008, because a common parent makes every package in the
 *     ecosystem wait on a release of the parent.
 *
 *     The coupling is real — renaming `Session::key()` would silently give
 *     every workspace a new address — and it is paid deliberately, which is a
 *     different thing from not having noticed it.
 *  3. An Eloquent model — morph class and key, hashed the same way the harness
 *     hashes a session address, so the two agree by construction rather than by
 *     coincidence.
 *  4. A string, for a job id or anything else an application already has.
 *
 * ## Why the address is slugged AND hashed
 *
 * `<slug>-<sha256:16>`, and it is a PUBLISHED, STABLE layout: anything reading
 * these directories from outside PHP — a backup job, a retention sweep, an
 * operator with `ls` — depends on it whether or not it is written down, so
 * changing it is a breaking change and is handled like one. Documented in the
 * README for the same reason.
 *
 * The readable part is for whoever opens the directory; the hash is what makes
 * it correct. Three things it fixes at once:
 *
 *  - A harness session key is `session:<hash>:<id>:<scope>`, and a colon is
 *    illegal in a Windows filename. An address that cannot be a directory on
 *    half the platforms is not an address.
 *  - Two owners whose keys differ only in case are DIFFERENT owners and the
 *    same directory on Windows and macOS. Without the hash, `user:Alice` and
 *    `user:alice` share a workspace.
 *  - Slugging is lossy, so two distinct keys can slug identically. The hash is
 *    taken over the raw key, before any of that.
 *
 * The result is then run back through the path guard, because an address is a
 * path segment and the one place a guarded package must not stop guarding is
 * the part it generates itself.
 */
final class WorkspaceAddress
{
    /** Long enough to read, short enough to leave room under Windows MAX_PATH. */
    private const SLUG_LENGTH = 48;

    /** 64 bits of the digest. Collision here means two owners share a workspace. */
    private const DIGEST_LENGTH = 16;

    public static function for(mixed $owner, ?PathGuard $guard = null): string
    {
        $address = self::slug(self::key($owner));

        // Guard our own output. A generated address is still a path segment,
        // and "we made it so it must be fine" is how the one unchecked path in
        // a package ends up being the one that matters.
        return ($guard ?? new PathGuard)->guard($address);
    }

    private static function key(mixed $owner): string
    {
        if ($owner instanceof WorkspaceOwner) {
            return $owner->workspaceKey();
        }

        if (is_object($owner) && method_exists($owner, 'key')) {
            $key = $owner->key();

            if (is_string($key) && $key !== '') {
                return $key;
            }
        }

        if ($owner instanceof Model) {
            return sprintf(
                '%s:%s',
                substr(sha1($owner->getMorphClass()), 0, 12),
                (string) $owner->getKey(),
            );
        }

        if (is_string($owner) && $owner !== '') {
            return $owner;
        }

        throw WorkspaceFailed::make(Fault::OwnerNotAddressable, sprintf(
            'A workspace cannot be addressed by [%s]. Implement %s, pass an Eloquent model, or pass a stable string.',
            get_debug_type($owner),
            WorkspaceOwner::class,
        ));
    }

    private static function slug(string $key): string
    {
        $slug = strtolower((string) preg_replace('/[^A-Za-z0-9]+/', '-', $key));
        $slug = trim($slug, '-');
        $slug = substr($slug, 0, self::SLUG_LENGTH);
        $slug = trim($slug, '-');

        return sprintf(
            '%s-%s',
            $slug === '' ? 'w' : $slug,
            substr(hash('sha256', $key), 0, self::DIGEST_LENGTH),
        );
    }
}
