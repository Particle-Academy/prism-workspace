<?php

declare(strict_types=1);

namespace Prism\Workspace\Exceptions;

/**
 * Failures that are not about the path.
 *
 * Separate from {@see Refusal} on purpose. A refusal means an agent tried to
 * leave its workspace and is a security event somebody will want to alert on; a
 * fault means the disk was full or the file was not there, which is operations.
 * Collapsing them into one code space would mean every "file not found" landed
 * in the same alert as an attempted escape, and an alert that fires on ordinary
 * conditions is an alert that gets muted.
 */
enum Fault: string
{
    case FileMissing = 'workspace_file_missing';
    case WriteFailed = 'workspace_write_failed';
    case DeleteFailed = 'workspace_delete_failed';
    case OwnerNotAddressable = 'workspace_owner_not_addressable';
}
