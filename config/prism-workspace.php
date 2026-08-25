<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Why this file is `prism-workspace.php` and not `workspace.php`
|--------------------------------------------------------------------------
|
| Because a published config file is a FILENAME in somebody else's config
| directory, and `workspace.php` is a name an application is entirely likely
| to want for itself.
|
| `prism-harness` ships `harness.php`, so matching a sibling and matching the
| ecosystem prefix pointed in opposite directions here. Decision 0010 settles
| it in favour of the prefix and records the harness's name as the mistake to
| correct rather than the convention to copy — which is the only reason this
| note exists: without it, the next agent comparing the two packages fixes the
| wrong one.
|
| Note that the config key and the GATE PREFIX are deliberately different
| namespaces and are not required to match. The config key has to survive in a
| directory shared with the whole application. The ability prefix names verbs
| this package owns, and `workspace.write` is what an application grants — see
| the authorization block below.
|
*/

return [

    /*
    |--------------------------------------------------------------------------
    | The disk workspaces live on
    |--------------------------------------------------------------------------
    |
    | Any disk from your own `filesystems.php`. A workspace is a `scoped` disk
    | pinned to a directory beneath it — Laravel's own driver, not something
    | this package invented, because Laravel already sandboxes a disk and
    | rebuilding that buys a second set of filesystem bugs and no capability.
    |
    | Defaults to `local` because every Laravel application has one. Point it at
    | S3 and everything works the same way: the guard runs in front of the disk,
    | not inside it.
    |
    */

    'disk' => env('PRISM_WORKSPACE_DISK', 'local'),

    /*
    |--------------------------------------------------------------------------
    | The directory workspaces live in, on that disk
    |--------------------------------------------------------------------------
    |
    | One subdirectory per owner beneath this. Keep it a directory of its own
    | rather than pointing it at the disk root: a workspace should sit next to
    | other workspaces and nothing else, so that a mistake is contained by the
    | layout as well as by the guard.
    |
    */

    'root' => env('PRISM_WORKSPACE_ROOT', 'workspaces'),

    /*
    |--------------------------------------------------------------------------
    | Path limits
    |--------------------------------------------------------------------------
    |
    | The per-segment limit is the real one: ext4 and NTFS both stop at 255
    | bytes per component. The whole-path budget is generous because the limit
    | that actually bites is the platform's, and on Windows that depends on
    | where your disk root is — which is a question about the filesystem, so it
    | is answered separately, below.
    |
    */

    'max_path_length' => 1024,

    'max_segment_length' => 255,

    /*
    |--------------------------------------------------------------------------
    | Windows MAX_PATH
    |--------------------------------------------------------------------------
    |
    | On Windows a full path stops at 260 characters unless long paths are
    | enabled, and a workspace root is already most of a hundred. Checked on
    | local disks only, and only when running on Windows.
    |
    | Set to null if you have enabled long path support and would rather find
    | out from the filesystem. The reason it is on by default is that the
    | failure it prevents is a truncation, and a truncated write is a file
    | somewhere nobody looked.
    |
    */

    'windows_max_path' => 259,

    /*
    |--------------------------------------------------------------------------
    | Authorization
    |--------------------------------------------------------------------------
    |
    | "May this agent do this here?" is an authorization question, and Laravel
    | has an answer to those. `prism-harness` already decided that tool
    | permissions are Gates and Policies; this package follows that rather than
    | inventing a second permission system with its own vocabulary.
    |
    | Turn this on and every operation calls `Gate::authorize()` with
    | `<prefix>.read`, `.write`, `.delete` or `.list`, passing the workspace and
    | the guarded path.
    |
    | OFF by default, and that is deliberate. The sandbox is the boundary; the
    | Gate is your policy on top of it. A default-on check would deny every
    | operation in a queue worker where there is no authenticated user — an
    | agent that silently stops writing files, in the context where nobody is
    | watching. The harness shipped a default that assumed infrastructure the
    | installing app had not claimed to have, and had to reverse it. Once is a
    | mistake; twice would be a convention.
    |
    */

    'authorize' => env('PRISM_WORKSPACE_AUTHORIZE', false),

    'gate_prefix' => env('PRISM_WORKSPACE_GATE_PREFIX', 'workspace'),

];
