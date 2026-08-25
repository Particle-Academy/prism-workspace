<?php

declare(strict_types=1);

namespace Prism\Workspace\Path;

use Prism\Workspace\Exceptions\PathRefused;
use Prism\Workspace\Exceptions\Refusal;

/**
 * The boundary, expressed as a pure function from a string to a safer string.
 *
 * Takes whatever an agent asked for and returns a relative path that is safe to
 * hand to a Laravel disk, or refuses it with a code. It never touches the
 * filesystem — not one stat, not one realpath — which is both a performance
 * property (this runs on every single operation) and a testability one: a
 * function of a string can be exhausted by a corpus, and a function of the disk
 * cannot.
 *
 * The one escape a string cannot express is the symlink, because a link is
 * filesystem state rather than a property of a name. That check lives in
 * {@see LocalBoundary}, where it is allowed to cost a syscall. Splitting the
 * two is what lets this class be held to the no-syscall rule at all.
 *
 * ## It refuses shapes, not dangers
 *
 * The single decision that shapes everything below: `..` is REFUSED, never
 * resolved. `docs/../report.md` lands inside the workspace and is perfectly
 * safe, and it is refused anyway.
 *
 * Resolving `..` correctly means being right on every input forever — the
 * pop-past-the-root off-by-one is the single most common way a path guard has
 * failed, in every language, for thirty years. Refusing the shape means being
 * right once. The cost is that an agent cannot write a path that doubles back
 * through a directory it just named, which no agent needs to do, and the corpus
 * records that cost as `str-0001` rather than leaving a consumer to find it.
 *
 * The same reasoning runs through the rest: refuse a colon rather than decide
 * whether this one is a drive or a stream; refuse a leading `~` rather than
 * predict which downstream consumer expands it; fold backslashes to separators
 * everywhere rather than let one string mean two things.
 *
 * ## Order is contract
 *
 * A path that is several things at once — `/../secret.txt` is absolute AND
 * traversing — gets exactly one code, and which one is decided by the order of
 * the checks below. That order is pinned by the corpus, because a consumer
 * alerting on `path_traverses_outside_workspace` should not have their alert go
 * quiet because a refactor moved a branch.
 */
final class PathGuard
{
    /**
     * Names Win32 resolves to hardware. Matched against the segment's name
     * BEFORE its first dot, because that is what Windows matches, and
     * case-insensitively, because so does Windows.
     *
     * The superscript forms are real: Win32 maps COM¹, COM² and COM³ onto the
     * first three serial ports, and no ASCII-only list contains them.
     */
    private const RESERVED_DEVICE_NAMES = [
        'CON', 'PRN', 'AUX', 'NUL', 'CLOCK$', 'CONIN$', 'CONOUT$',
        'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
        "COM\u{00B9}", "COM\u{00B2}", "COM\u{00B3}",
        "LPT\u{00B9}", "LPT\u{00B2}", "LPT\u{00B3}",
    ];

    /**
     * Percent sequences that decode to a separator, a dot, another percent, a
     * null, or any non-ASCII byte.
     *
     * Nothing here decodes anything, so unguarded these would simply become
     * oddly-named files. They are refused because something downstream always
     * decodes — and because an agent asking for `%2e%2e%2f` is asking for
     * `../`, whatever the intervening layers do with it. The non-ASCII arm
     * covers overlong UTF-8, which is how `%c0%ae` becomes `.` in a lenient
     * decoder.
     *
     * Deliberately narrow: `50% off.md` and `report%2d.txt` are files, not
     * attacks, and both survive this.
     */
    private const ENCODED_SEPARATOR = '/%(?:00|25|2e|2f|5c|[89a-f][0-9a-f])|%u[0-9a-f]{4}/i';

    /** Format characters that render as nothing, or as the wrong direction. */
    private const INVISIBLE = '/[\x{00AD}\x{061C}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}]/u';

    /** Characters that read as a separator and are not one. */
    private const SEPARATOR_HOMOGLYPH = '/[\x{2044}\x{2215}\x{29F5}\x{29F8}\x{FE68}\x{FF0F}\x{FF3C}]/u';

    /** The 8.3 alias shape. Also the shape of some real filenames — see str-0003. */
    private const SHORT_NAME_ALIAS = '/^[^.\/]{1,6}~[0-9]{1,4}(?:\.[^.\/]{1,3})?$/u';

    /** A leading `~`, `~user`, or `~/…`. Not `~$draft.docx`, which is a file Word left behind. */
    private const HOME_EXPANSION = '/^~[\w.-]*$/u';

    public function __construct(
        /**
         * A budget for the whole relative path. Generous by default: the limit
         * that actually bites is the platform's, and on Windows that depends on
         * where the disk root is — which is a question about the filesystem, so
         * it belongs to LocalBoundary and not here.
         */
        private readonly int $maxPathLength = 1024,
        /** ext4 and NTFS both stop at 255 bytes per component. */
        private readonly int $maxSegmentLength = 255,
    ) {}

    /**
     * @throws PathRefused
     */
    public function guard(string $path): string
    {
        if ($path === '') {
            throw PathRefused::make(Refusal::EmptyPath, $path, 'it is empty, and there is no version of writing to the workspace directory itself that a caller meant');
        }

        if (strlen($path) > $this->maxPathLength) {
            throw PathRefused::make(Refusal::TooLong, $path, sprintf('it is %d bytes, over the %d-byte budget', strlen($path), $this->maxPathLength));
        }

        // Null first: it is valid UTF-8, so an encoding check would pass it
        // straight through to a C boundary that truncates there.
        if (str_contains($path, "\0")) {
            throw PathRefused::make(Refusal::NullByte, $path, 'it contains a null byte, which truncates the name at the syscall while every check above sees the whole string');
        }

        if (! mb_check_encoding($path, 'UTF-8')) {
            throw PathRefused::make(Refusal::InvalidEncoding, $path, 'it is not valid UTF-8, so no two layers here would agree on what it says');
        }

        // Everything below this line may use /u safely.
        if (preg_match(self::INVISIBLE, $path) === 1) {
            throw PathRefused::make(Refusal::InvisibleCharacter, $path, 'it contains an invisible or direction-changing character, which makes the name render as something it is not');
        }

        if (preg_match(self::SEPARATOR_HOMOGLYPH, $path) === 1) {
            throw PathRefused::make(Refusal::SeparatorHomoglyph, $path, 'it contains a character that reads as a separator and is not one, so the name would look like a path it is not');
        }

        if (preg_match('/[\x01-\x1F\x7F]/', $path) === 1) {
            throw PathRefused::make(Refusal::ControlCharacter, $path, 'it contains a control character, which is illegal on Windows and rewrites any log the name is printed into');
        }

        if (preg_match(self::ENCODED_SEPARATOR, $path) === 1) {
            throw PathRefused::make(Refusal::EncodedSeparator, $path, 'it contains a percent-encoded separator, dot, or non-ASCII byte, which is a traversal waiting for whatever decodes next');
        }

        // Absolute forms are checked BEFORE separators are folded, because two
        // of them are only recognisable in their raw spelling.
        if (str_starts_with($path, '\\\\') || str_starts_with($path, '//')) {
            throw PathRefused::make(Refusal::Unc, $path, 'it begins with a doubled separator, which is a UNC or device-namespace path on Windows and implementation-defined on POSIX');
        }

        if (preg_match('/^[A-Za-z]:/', $path) === 1) {
            throw PathRefused::make(Refusal::Absolute, $path, 'it is anchored to a drive, which is not this workspace');
        }

        // One meaning per input: a backslash is always a separator, everywhere.
        // On POSIX that costs a legal filename character nobody should want; it
        // buys a workspace that means the same thing on both platforms.
        $folded = str_replace('\\', '/', $path);

        if (str_starts_with($folded, '/')) {
            throw PathRefused::make(Refusal::Absolute, $path, 'it is anchored to the filesystem root, which is not this workspace');
        }

        $kept = [];

        foreach (explode('/', $folded) as $index => $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            $this->guardSegment($path, $segment, $index === 0);

            $kept[] = $segment;
        }

        $normalised = implode('/', $kept);

        if ($normalised === '') {
            throw PathRefused::make(Refusal::EmptyPath, $path, 'it normalises to nothing at all');
        }

        return $normalised;
    }

    private function guardSegment(string $path, string $segment, bool $leading): void
    {
        // Refused as a SHAPE. `..` anything — `..`, `...`, `..;`, `....` — is
        // out, which is why this is the first check and why it never has to
        // reason about where the path would land. See the class docblock.
        if (str_starts_with($segment, '..')) {
            throw PathRefused::make(Refusal::Traversal, $path, 'a segment begins with two dots, and this package refuses that shape rather than resolving it');
        }

        // A colon is a drive on Windows and an NTFS stream on NTFS. The drive
        // reading was already refused above, so anything reaching here is the
        // stream reading: bytes stored under a name that no directory listing
        // and no audit will ever show.
        if (str_contains($segment, ':')) {
            throw PathRefused::make(Refusal::AlternateDataStream, $path, 'a segment contains a colon, which names an alternate data stream that no directory listing shows');
        }

        if (str_ends_with($segment, '.') || str_ends_with($segment, ' ') || str_starts_with($segment, ' ')) {
            throw PathRefused::make(Refusal::EdgeDotOrSpace, $path, 'a segment begins or ends with a dot or a space, which Win32 strips — so this name and the stripped one are the same file');
        }

        if ($leading && preg_match(self::HOME_EXPANSION, $segment) === 1) {
            throw PathRefused::make(Refusal::HomeExpansion, $path, 'it begins with a home-directory reference, which PHP leaves alone and almost everything a path is handed to next does not');
        }

        if (preg_match(self::SHORT_NAME_ALIAS, $segment) === 1) {
            throw PathRefused::make(Refusal::ShortNameAlias, $path, 'a segment has the shape of an 8.3 short name, which on NTFS is a second name for a file the listing shows differently');
        }

        if (in_array(mb_strtoupper($this->deviceName($segment), 'UTF-8'), self::RESERVED_DEVICE_NAMES, true)) {
            throw PathRefused::make(Refusal::ReservedDeviceName, $path, 'a segment names a Windows device rather than a file, so a write to it either blocks or is silently discarded');
        }

        if (strlen($segment) > $this->maxSegmentLength) {
            throw PathRefused::make(Refusal::SegmentTooLong, $path, sprintf('a segment is %d bytes, over the %d-byte limit both ext4 and NTFS enforce', strlen($segment), $this->maxSegmentLength));
        }
    }

    /**
     * The part Win32 matches against its device list: everything before the
     * first dot. `nul.log` is the console, `nullify.txt` is a file.
     */
    private function deviceName(string $segment): string
    {
        $dot = strpos($segment, '.');

        return $dot === false ? $segment : substr($segment, 0, $dot);
    }
}
