<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

/**
 * What an escape attempt exploits.
 *
 * Grouping cases by mechanism rather than by syntax is what makes the corpus
 * auditable: a reader can ask "is every way of writing an absolute path
 * covered?" and get an answer, which is not a question a flat list of strings
 * can be asked.
 */
enum Hazard: string
{
    /** `..` in any spelling — the classic, and still the one that lands. */
    case Traversal = 'traversal';

    /** A path anchored somewhere other than the workspace root. */
    case AbsolutePath = 'absolute-path';

    /** UNC and the Win32 device namespaces — absolute paths that do not look absolute. */
    case UncPath = 'unc-path';

    /** Names Windows resolves to hardware rather than to files. */
    case DeviceName = 'device-name';

    /** NTFS alternate data streams — content hidden behind a name a listing shows. */
    case AlternateDataStream = 'alternate-data-stream';

    /** Two names, one file: trailing dots, edge spaces, 8.3 aliases, case folding. */
    case NameAliasing = 'name-aliasing';

    /** A separator that is only a separator after somebody else decodes it. */
    case EncodedSeparator = 'encoded-separator';

    /** Bytes that truncate, corrupt, or forge the record of what was asked for. */
    case ByteInjection = 'byte-injection';

    /** Names that render as something other than what they are. */
    case Deception = 'deception';

    /** Lengths the platform cannot store, or stores by silently truncating. */
    case Length = 'length';

    /** A path that resolves to nothing at all. */
    case EmptyPath = 'empty-path';

    /**
     * Input that is genuinely safe and refused anyway.
     *
     * These are in the corpus on purpose. A guard that refuses only dangerous
     * things has to decide what is dangerous on every call; a guard that
     * refuses a whole SHAPE never makes that decision. The cost is real and is
     * recorded here rather than discovered by a consumer.
     */
    case Strictness = 'strictness';
}
