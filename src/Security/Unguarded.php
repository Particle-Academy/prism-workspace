<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

/**
 * What happens to an attempt when NOTHING is guarding the workspace.
 *
 * This is the half of the corpus that stops it being decorative. A case
 * asserting only that the guard refuses something proves the guard is
 * consistent with itself; it does not prove the input was ever dangerous. Each
 * case therefore also records what an unguarded resolver does with it, and the
 * suite proves that claim by executing it.
 *
 * It is recorded PER PLATFORM because the answer differs, and the difference is
 * the reason this package's CI runs on Windows as well as Linux. `C:\Windows`
 * escapes on Windows and is an ordinary filename containing backslashes on
 * Linux — which is not "safe on Linux", because that file travels: written by
 * a Linux worker, read by a Windows one, and now it is an escape.
 */
enum Unguarded: string
{
    /**
     * A naive join of root and path resolves OUTSIDE the root.
     *
     * Provable without a filesystem, and the suite proves it lexically for
     * every case carrying this value.
     */
    case Escapes = 'escapes';

    /**
     * Lands inside the root as a string, but the platform resolves the name to
     * something other than a plain file at that relative path — a device, a
     * hidden stream, an alias for a different file.
     */
    case Reaches = 'reaches';

    /**
     * Lands inside the root and creates an ordinary file, but the NAME defeats
     * whatever inspects it next: a second decoder, a log, a reviewer's eyes, or
     * the same workspace opened on the other platform.
     *
     * Not an escape on its own. Recorded as what it is rather than inflated.
     */
    case Confuses = 'confuses';

    /**
     * Nothing bad happens. The input is safe and this package refuses it
     * anyway — see Hazard::Strictness.
     */
    case Harmless = 'harmless';
}
