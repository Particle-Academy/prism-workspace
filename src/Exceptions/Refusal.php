<?php

declare(strict_types=1);

namespace Prism\Workspace\Exceptions;

/**
 * Why a path was refused — the machine-readable half of a failure.
 *
 * Codes are the contract; the sentence a human reads is not. That is the
 * ecosystem's decision 0004 and it applies here for the same reason it applies
 * to the ports: a consumer branching on a failure should not be matching on
 * English, and improving a message should not be a breaking change.
 *
 * It matters more here than it does elsewhere. A refusal from this package is
 * a security event. Somebody is going to want to alert on "an agent tried to
 * write outside its workspace" and they should be able to do that on
 * `path_traverses_outside_workspace` rather than on a substring that gets
 * reworded in a patch release.
 */
enum Refusal: string
{
    case Traversal = 'path_traverses_outside_workspace';
    case Absolute = 'path_is_absolute';
    case Unc = 'path_is_unc_or_device_namespace';
    case NullByte = 'path_contains_null_byte';
    case ControlCharacter = 'path_contains_control_character';
    case InvisibleCharacter = 'path_contains_invisible_character';
    case SeparatorHomoglyph = 'path_contains_separator_homoglyph';
    case InvalidEncoding = 'path_is_not_valid_utf8';
    case EncodedSeparator = 'path_contains_encoded_separator';
    case AlternateDataStream = 'path_contains_alternate_data_stream';
    case ReservedDeviceName = 'path_is_reserved_device_name';
    case EdgeDotOrSpace = 'path_has_edge_dot_or_space';
    case ShortNameAlias = 'path_uses_short_name_alias';
    case HomeExpansion = 'path_uses_home_expansion';
    case EmptyPath = 'path_is_empty';
    case TooLong = 'path_too_long';
    case SegmentTooLong = 'path_segment_too_long';

    /**
     * Lexically fine, and still outside — because a directory on the way was a
     * link. The only refusal in this enum that a string cannot produce.
     */
    case EscapesViaLink = 'path_escapes_workspace_via_link';
}
