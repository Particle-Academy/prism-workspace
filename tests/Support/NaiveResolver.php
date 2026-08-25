<?php

declare(strict_types=1);

namespace Tests\Support;

/**
 * A workspace with no guard on it.
 *
 * This is the thing the corpus is proven against. It is not a straw man: it is
 * `join(root, path)` with the platform's own rules, which is what `os.path.join`
 * does in Python, what `Path.Combine` does in .NET, what `path.resolve` does in
 * Node, and what happens the instant a PHP path reaches a native function. The
 * one rule that matters is the one people forget: **an absolute second argument
 * REPLACES the first.**
 *
 * Purely lexical. It never touches a filesystem, which is what lets the Linux
 * CI job prove the Windows claims and the Windows job prove the POSIX ones.
 * Platform-gating those assertions would mean half the corpus was only ever
 * checked by half the matrix, and the half nobody ran would be the half that
 * rotted.
 */
final class NaiveResolver
{
    public const POSIX = 'posix';

    public const WINDOWS = 'windows';

    /**
     * @return list<string>
     */
    public static function platforms(): array
    {
        return [self::POSIX, self::WINDOWS];
    }

    public static function isAbsolute(string $path, string $platform): bool
    {
        if ($path === '') {
            return false;
        }

        if (str_starts_with($path, '/')) {
            return true;
        }

        if ($platform === self::POSIX) {
            return false;
        }

        // Windows: a drive letter, a drive-root-relative backslash, or a UNC
        // prefix in either spelling.
        return str_starts_with($path, '\\')
            || preg_match('/^[A-Za-z]:/', $path) === 1;
    }

    /**
     * Join and then resolve `.` and `..`, lexically.
     */
    public static function resolve(string $root, string $path, string $platform): string
    {
        $joined = self::isAbsolute($path, $platform)
            ? $path
            : rtrim($root, '/').'/'.$path;

        return self::canonicalise($joined, $platform);
    }

    public static function inside(string $root, string $candidate, string $platform): bool
    {
        $root = self::canonicalise($root, $platform);

        if ($platform === self::WINDOWS) {
            // NTFS folds case, so a containment check that does not is a
            // containment check that can be walked around with the shift key.
            $root = mb_strtolower($root, 'UTF-8');
            $candidate = mb_strtolower($candidate, 'UTF-8');
        }

        return $candidate === $root || str_starts_with($candidate, rtrim($root, '/').'/');
    }

    private static function canonicalise(string $path, string $platform): string
    {
        // Windows accepts both separators. POSIX has exactly one, and a
        // backslash there is an ordinary character in a filename — which is the
        // whole reason half this corpus is classified differently per platform.
        $normalised = $platform === self::WINDOWS
            ? str_replace('\\', '/', $path)
            : $path;

        $anchor = '';

        if (str_starts_with($normalised, '/')) {
            $anchor = '/';
        } elseif ($platform === self::WINDOWS && preg_match('/^[A-Za-z]:/', $normalised) === 1) {
            $anchor = substr($normalised, 0, 2).'/';
            $normalised = substr($normalised, 2);
        }

        $resolved = [];

        foreach (explode('/', $normalised) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                // Every OS clamps at the root rather than erroring, so popping
                // an empty stack is a no-op and not a failure.
                array_pop($resolved);

                continue;
            }

            $resolved[] = $segment;
        }

        return $anchor.implode('/', $resolved);
    }
}
