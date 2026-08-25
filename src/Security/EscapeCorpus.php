<?php

declare(strict_types=1);

namespace Prism\Workspace\Security;

use Countable;
use InvalidArgumentException;
use Prism\Workspace\Exceptions\Refusal;

/**
 * Every way out of a workspace that a string can express.
 *
 * This ships in the distributed package rather than being export-ignored with
 * the rest of `/tests`, and that is the point of it. A sandbox boundary nobody
 * outside the project can verify is a claim; one that arrives with the suite
 * that attacks it is evidence. Point `CorpusRunner` at a workspace built from
 * YOUR disk configuration and find out, rather than trusting ours.
 *
 * The corpus is meant to be EXHAUSTIVE per hazard rather than representative.
 * Representative is how a guard ends up covering `../` and missing `..\`, which
 * is the same hazard spelled for the other platform.
 *
 * What is deliberately NOT here: symlinks and case-folding collisions. Neither
 * is a property of a string — a symlink is filesystem state and a case
 * collision needs two writes — so neither can be refused by inspecting a path.
 * They are covered by their own tests. A corpus that quietly omitted them would
 * be claiming a completeness it does not have.
 */
final class EscapeCorpus implements Countable
{
    /**
     * Bump when cases are added or their claims change, so a consumer pinning
     * this package can tell whether their last run covered what this one does.
     */
    public const VERSION = '1';

    /** @var list<EscapeAttempt>|null */
    private static ?array $cases = null;

    /**
     * @return list<EscapeAttempt>
     */
    public static function all(): array
    {
        return self::$cases ??= array_merge(
            self::traversal(),
            self::absolutePaths(),
            self::uncAndDeviceNamespaces(),
            self::homeExpansion(),
            self::reservedDeviceNames(),
            self::alternateDataStreams(),
            self::nameAliasing(),
            self::encodedSeparators(),
            self::byteInjection(),
            self::deception(),
            self::lengths(),
            self::emptyPaths(),
            self::strictness(),
        );
    }

    /**
     * @return list<EscapeAttempt>
     */
    public static function withHazard(Hazard $hazard): array
    {
        return array_values(array_filter(self::all(), fn (EscapeAttempt $case): bool => $case->hazard === $hazard));
    }

    /**
     * @return list<EscapeAttempt>
     */
    public static function withUnguardedOutcome(Unguarded $outcome): array
    {
        return array_values(array_filter(self::all(), fn (EscapeAttempt $case): bool => $case->unguarded() === $outcome));
    }

    public static function get(string $id): EscapeAttempt
    {
        foreach (self::all() as $case) {
            if ($case->id === $id) {
                return $case;
            }
        }

        throw new InvalidArgumentException("No escape attempt with id [{$id}].");
    }

    public function count(): int
    {
        return count(self::all());
    }

    /**
     * `..`, in every spelling the two platforms accept.
     *
     * @return list<EscapeAttempt>
     */
    private static function traversal(): array
    {
        $c = fn (string $id, string $path, Unguarded $posix, Unguarded $windows, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::Traversal, Refusal::Traversal, $posix, $windows, $note,
        );

        return [
            $c('trv-0001', '..', Unguarded::Escapes, Unguarded::Escapes,
                'The whole attack, unadorned. If nothing else in this corpus runs, this one must.'),
            $c('trv-0002', '../', Unguarded::Escapes, Unguarded::Escapes,
                'Trailing separator. Some normalisers treat a directory reference differently from a file one.'),
            $c('trv-0003', '../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'One level up, which is where a sibling workspace lives.'),
            $c('trv-0004', '../../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Two levels up: out of the workspaces directory entirely.'),
            $c('trv-0005', '../../../../../../../../../../etc/passwd', Unguarded::Escapes, Unguarded::Escapes,
                'More levels than the root has. Every OS clamps at the filesystem root rather than erroring, so overshooting is free.'),
            $c('trv-0006', 'a/../../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Descend first. Defeats any check that only looks at the leading characters.'),
            $c('trv-0007', 'a/b/../../../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Descend two, ascend three. The off-by-one that a hand-written pop loop gets wrong.'),
            $c('trv-0008', './../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'A no-op segment in front, which is enough to defeat a `str_starts_with(.., "..")` check.'),
            $c('trv-0009', '.././secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'A no-op segment in the middle.'),
            $c('trv-0010', 'a/./../../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'No-ops interleaved with real movement.'),
            $c('trv-0011', '..//secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Doubled separator. An empty segment must collapse, not count as a level.'),
            $c('trv-0012', '../.././secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Mixed no-ops and ascents.'),
            $c('trv-0013', 'a/../..', Unguarded::Escapes, Unguarded::Escapes,
                'Ends on the ascent, with no filename after it.'),
            $c('trv-0014', 'subdir/../../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'The shape a model actually produces when it has lost track of where it is.'),
            $c('trv-0015', '..\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Backslash separator. Escapes on Windows; on Linux it is a FILENAME containing a backslash — which is not safe, it is a file that becomes an escape the moment the workspace is opened on Windows.'),
            $c('trv-0016', '..\\..\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Two levels, Windows spelling.'),
            $c('trv-0017', 'a\\..\\..\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Descend-then-ascend, Windows spelling.'),
            $c('trv-0018', '../\\secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Mixed separators. Whichever one a normaliser handles, the other is the one used.'),
            $c('trv-0019', '..\\/secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Mixed separators the other way round.'),
            $c('trv-0020', '...', Unguarded::Confuses, Unguarded::Reaches,
                'Three dots. A legal directory name on POSIX; Win32 strips trailing dots from each component, so what the filesystem sees is version-dependent — which is the reason to refuse it rather than to model it.'),
            $c('trv-0021', '....//secret.txt', Unguarded::Confuses, Unguarded::Reaches,
                'The classic single-pass-filter bypass: strip one `../` from this and you are left with `../`.'),
            $c('trv-0022', '..;/secret.txt', Unguarded::Confuses, Unguarded::Confuses,
                'The `..;` token, which several routers and proxies normalise back to `..` before anything else sees it.'),
            $c('trv-0023', '../secret.txt.bak', Unguarded::Escapes, Unguarded::Escapes,
                'Traversal wearing an innocuous extension, in case a guard branches on file type before it branches on shape.'),
        ];
    }

    /**
     * Paths anchored somewhere other than the workspace.
     *
     * @return list<EscapeAttempt>
     */
    private static function absolutePaths(): array
    {
        $c = fn (string $id, string $path, Unguarded $posix, Unguarded $windows, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::AbsolutePath, Refusal::Absolute, $posix, $windows, $note,
        );

        return [
            $c('abs-0001', '/etc/passwd', Unguarded::Escapes, Unguarded::Escapes,
                'The canonical one. Note that a leading slash is drive-root-relative on Windows too, so this escapes on both.'),
            $c('abs-0002', '/', Unguarded::Escapes, Unguarded::Escapes,
                'The filesystem root itself.'),
            $c('abs-0003', '/../secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Absolute AND traversing. Refused as absolute because that check comes first; the ORDER of checks is part of the contract, since it decides which code a consumer alerts on.'),
            $c('abs-0004', '/proc/self/environ', Unguarded::Escapes, Unguarded::Escapes,
                'Where a Linux process keeps its environment, which is where the API keys are.'),
            $c('abs-0005', '/dev/stdin', Unguarded::Escapes, Unguarded::Escapes,
                'A read that blocks forever is a denial of service that looks like a slow model.'),
            $c('abs-0006', 'C:\\Windows\\System32\\config\\SAM', Unguarded::Confuses, Unguarded::Escapes,
                'Drive-qualified. On Linux this is one long filename — stored happily, and an escape as soon as the disk is mounted by a Windows worker.'),
            $c('abs-0007', 'C:/Windows/win.ini', Unguarded::Confuses, Unguarded::Escapes,
                'Windows accepts forward slashes, so a guard that only rejects backslashes rejects nothing.'),
            $c('abs-0008', 'c:/windows/win.ini', Unguarded::Confuses, Unguarded::Escapes,
                'Lowercase drive letter, because a case-sensitive check on `C:` is a check on nothing.'),
            $c('abs-0009', 'C:secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Drive-RELATIVE: resolves against whatever the current directory on C: happens to be. No separator anywhere, so it does not look like a path at all.'),
            $c('abs-0010', 'Z:/', Unguarded::Confuses, Unguarded::Escapes,
                'A mapped network drive, which is somebody else\'s filesystem.'),
            $c('abs-0011', '\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Root of the current drive on Windows.'),
            $c('abs-0012', '\\Windows\\win.ini', Unguarded::Confuses, Unguarded::Escapes,
                'Root-relative with a real target.'),
            $c('abs-0013', 'a:b', Unguarded::Confuses, Unguarded::Escapes,
                'Genuinely ambiguous: a one-letter directory with an alternate data stream, or drive `a:` relative. Windows reads it as the drive, so this is refused as absolute rather than as a stream.'),
            $c('abs-0014', '/var/www/.env', Unguarded::Escapes, Unguarded::Escapes,
                'The single highest-value file on a Laravel host, and the one a compromised agent asks for first.'),
        ];
    }

    /**
     * Absolute paths that do not begin with a drive letter or a slash.
     *
     * @return list<EscapeAttempt>
     */
    private static function uncAndDeviceNamespaces(): array
    {
        $c = fn (string $id, string $path, Unguarded $posix, Unguarded $windows, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::UncPath, Refusal::Unc, $posix, $windows, $note,
        );

        return [
            $c('unc-0001', '\\\\server\\share\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'A UNC path reaches a machine that is not this one. Exfiltration by write, with no outbound HTTP for anything to notice.'),
            $c('unc-0002', '//server/share/secret.txt', Unguarded::Escapes, Unguarded::Escapes,
                'Windows accepts the forward-slash UNC form. On POSIX a doubled leading slash is implementation-defined, so it is refused on both platforms for the same reason: one input must get one answer.'),
            $c('unc-0003', '\\\\?\\C:\\Windows\\win.ini', Unguarded::Confuses, Unguarded::Escapes,
                'The extended-length prefix. It also DISABLES Win32 path normalisation, so every assumption a guard made about trailing dots stops holding.'),
            $c('unc-0004', '\\\\.\\PhysicalDrive0', Unguarded::Confuses, Unguarded::Escapes,
                'The device namespace: raw block-device access, not a file.'),
            $c('unc-0005', '\\\\?\\UNC\\server\\share\\secret.txt', Unguarded::Confuses, Unguarded::Escapes,
                'Extended-length UNC — remote and un-normalised at once.'),
            $c('unc-0006', '///etc/passwd', Unguarded::Escapes, Unguarded::Escapes,
                'Three leading slashes, because a check for exactly two is a check for exactly two.'),
            $c('unc-0007', '\\\\localhost\\c$\\Windows\\win.ini', Unguarded::Confuses, Unguarded::Escapes,
                'The admin share: the whole local C: drive, reached over a network path, from the local machine.'),
            $c('unc-0008', '//?/C:/Windows/win.ini', Unguarded::Escapes, Unguarded::Escapes,
                'Extended-length prefix in its forward-slash spelling.'),
        ];
    }

    /**
     * @return list<EscapeAttempt>
     */
    private static function homeExpansion(): array
    {
        $c = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::AbsolutePath, Refusal::HomeExpansion, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        return [
            $c('hom-0001', '~/.ssh/id_rsa', 'PHP does not expand `~`, so this lands inside as a directory literally named `~`. It is refused because everything a workspace hands a path to next — a shell, a build tool, a Python process, anything execution would introduce — does expand it.'),
            $c('hom-0002', '~', 'The bare form.'),
            $c('hom-0003', '~root/.bashrc', 'Another user\'s home. Refused only when `~` leads the path; a file named `~$draft.docx`, which is what Word leaves behind, is fine.'),
        ];
    }

    /**
     * Names that are hardware.
     *
     * @return list<EscapeAttempt>
     */
    private static function reservedDeviceNames(): array
    {
        $c = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::DeviceName, Refusal::ReservedDeviceName, Unguarded::Confuses, Unguarded::Reaches, $note,
        );

        return [
            $c('dev-0001', 'CON', 'The console. A write succeeds and produces no file; a read blocks on input that never comes.'),
            $c('dev-0002', 'PRN', 'The printer.'),
            $c('dev-0003', 'AUX', 'The auxiliary device.'),
            $c('dev-0004', 'NUL', 'The bit bucket. A write "succeeds" and the artifact is simply gone — the worst failure mode here, because nothing reports it.'),
            $c('dev-0005', 'CLOCK$', 'The system clock.'),
            $c('dev-0006', 'COM1', 'A serial port.'),
            $c('dev-0007', 'COM9', 'The last of them, in case a check hardcoded COM1 through COM4.'),
            $c('dev-0008', 'LPT1', 'A parallel port.'),
            $c('dev-0009', 'LPT9', 'As above.'),
            $c('dev-0010', 'CONIN$', 'Console input, which is not in most published lists of reserved names.'),
            $c('dev-0011', 'CONOUT$', 'Console output, likewise.'),
            $c('dev-0012', 'con', 'Lowercase. Device names are case-insensitive, so a case-sensitive list catches nothing.'),
            $c('dev-0013', 'CON.txt', 'An extension does not help: Win32 matches the name before the first dot.'),
            $c('dev-0014', 'nul.log', 'The most plausible accident in this whole corpus — an agent writing a log to a file it named `nul`.'),
            $c('dev-0015', 'reports/COM1.txt', 'Reserved in every directory, not only the root.'),
            $c('dev-0016', 'AUX.tar.gz', 'Two extensions; still the name before the first dot that counts.'),
            $c('dev-0017', "COM\u{00B9}", 'Superscript one. Win32 maps the superscript digits onto COM1-COM3, and no ASCII-only check sees it.'),
        ];
    }

    /**
     * Content behind a name a listing shows.
     *
     * @return list<EscapeAttempt>
     */
    private static function alternateDataStreams(): array
    {
        $c = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::AlternateDataStream, Refusal::AlternateDataStream, Unguarded::Confuses, Unguarded::Reaches, $note,
        );

        return [
            $c('ads-0001', 'notes.txt:hidden', 'An NTFS alternate data stream. The bytes are stored, the directory listing shows `notes.txt` at its original size, and nothing an audit walks will find them.'),
            $c('ads-0002', 'notes.txt:hidden:$DATA', 'The explicit stream-type form.'),
            $c('ads-0003', 'notes.txt::$DATA', 'The default stream named explicitly — an old way of reading a file past a filter that matched on the exact name.'),
            $c('ads-0004', 'reports/summary.md:notes', 'In a subdirectory.'),
            $c('ads-0005', ':secret', 'A stream on the directory itself.'),
        ];
    }

    /**
     * Two names, one file.
     *
     * @return list<EscapeAttempt>
     */
    private static function nameAliasing(): array
    {
        $edge = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::NameAliasing, Refusal::EdgeDotOrSpace, Unguarded::Confuses, Unguarded::Reaches, $note,
        );

        $short = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::NameAliasing, Refusal::ShortNameAlias, Unguarded::Confuses, Unguarded::Reaches, $note,
        );

        return [
            $edge('ali-0001', 'secret.txt.', 'Win32 strips the trailing dot, so this IS `secret.txt` — a write that overwrites a file the caller believes it is not touching.'),
            $edge('ali-0002', 'secret.txt...', 'Several dots, same collapse.'),
            $edge('ali-0003', 'secret.txt ', 'Trailing space, same collapse, and invisible in every log that prints it.'),
            $edge('ali-0004', ' secret.txt', 'Leading space. Preserved by some Win32 entry points and trimmed by others, which means the two ends of a copy can disagree about which file was meant.'),
            $edge('ali-0005', 'reports./summary.md', 'The alias on a DIRECTORY component, so the whole subtree lands somewhere else.'),
            $edge('ali-0006', 'reports /summary.md', 'The space form of the same.'),
            $edge('ali-0007', '   ', 'Only spaces: a name that survives an emptiness check and then collapses to nothing.'),
            $short('ali-0008', 'PROGRA~1/secret.txt', 'An 8.3 short name. On NTFS with short names enabled it aliases a long directory the listing shows under a completely different name.'),
            $short('ali-0009', 'MYDOCU~1.TXT', 'The file form.'),
            $short('ali-0010', 'reports/DOCUME~2', 'A second-generation alias, which is what you get once two long names share the first six characters.'),
        ];
    }

    /**
     * Separators that are only separators after somebody else decodes them.
     *
     * @return list<EscapeAttempt>
     */
    private static function encodedSeparators(): array
    {
        $c = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::EncodedSeparator, Refusal::EncodedSeparator, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        return [
            $c('enc-0001', '%2e%2e%2fsecret.txt', 'Percent-encoded `../`. This package never decodes, so unguarded it would simply create a strangely named file — refused because SOMETHING downstream decodes, and an agent asking for this is asking for traversal either way.'),
            $c('enc-0002', '%2E%2E%2Fsecret.txt', 'Uppercase hex.'),
            $c('enc-0003', '..%2fsecret.txt', 'Half-encoded: the dots plain, the separator encoded.'),
            $c('enc-0004', '..%5csecret.txt', 'The backslash form.'),
            $c('enc-0005', '%2e%2e/secret.txt', 'The other half encoded.'),
            $c('enc-0006', '%252e%252e%252fsecret.txt', 'Double-encoded. Survives exactly one decode, which is how many decodes most pipelines do.'),
            $c('enc-0007', '%c0%ae%c0%ae%c0%afsecret.txt', 'Overlong UTF-8 for `.` and `/`. Rejected by any conformant decoder and accepted by a surprising number of real ones.'),
            $c('enc-0008', '%c1%9csecret.txt', 'Overlong backslash — the IIS Unicode bug, still reachable through any lenient decoder.'),
            $c('enc-0009', '%uff0e%uff0e%u2215secret.txt', 'The `%u` form, which is not standards-based and which several Windows components accept anyway.'),
            $c('enc-0010', '..%00/secret.txt', 'Encoded null: truncates the path in any consumer that decodes and then hands the result to C.'),
            $c('enc-0011', '%2fetc%2fpasswd', 'An encoded absolute path.'),
            $c('enc-0012', '%5c%5cserver%5cshare', 'An encoded UNC path.'),
            $c('enc-0013', '..%252fsecret.txt', 'Mixed single and double encoding, to defeat a decoder that loops until the string stops changing.'),
            $c('enc-0014', '%2e%2e%5csecret.txt', 'Encoded dots with an encoded backslash.'),
        ];
    }

    /**
     * Bytes that truncate, corrupt, or forge the record of what was asked for.
     *
     * @return list<EscapeAttempt>
     */
    private static function byteInjection(): array
    {
        $nul = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::ByteInjection, Refusal::NullByte, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        $ctrl = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::ByteInjection, Refusal::ControlCharacter, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        $enc = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::ByteInjection, Refusal::InvalidEncoding, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        return [
            $nul('byt-0001', "secret\x00.txt", 'A null byte truncates at the C boundary, so a PHP-level check sees `secret\\0.txt` and the syscall sees `secret`.'),
            $nul('byt-0002', "secret.txt\x00.png", 'The extension-check bypass: PHP sees a `.png`, the filesystem sees a `.txt`.'),
            $nul('byt-0003', "\x00", 'A path that is one null byte. Not empty by any string test, and nothing at all by the time it lands.'),
            $ctrl('byt-0004', "notes\x01.txt", 'A control character. Illegal in a Windows filename, legal on Linux, so the same workspace is portable in one direction only.'),
            $ctrl('byt-0005', "notes\n.txt", 'A newline. Every log line about this file becomes two, one of which the agent wrote.'),
            $ctrl('byt-0006', "notes\r\n.txt", 'CRLF, for the log formats that split on it.'),
            $ctrl('byt-0007', "notes\t.txt", 'A tab, for the ones that split on that.'),
            $ctrl('byt-0008', "notes\x7f.txt", 'DEL. Above the printable range rather than below it, which is where a `< 0x20` check stops looking.'),
            $ctrl('byt-0009', "notes\x1b[2Jclear.txt", 'An ANSI escape sequence. Printing this listing to a terminal clears the terminal — the agent editing what its operator sees.'),
            $enc('byt-0010', "\xC3\x28", 'Invalid UTF-8. What a byte-oriented filesystem stores and a UTF-8 API cannot round-trip.'),
            $enc('byt-0011', "\xED\xA0\x80", 'A lone surrogate encoded as UTF-8, which is not UTF-8.'),
            $enc('byt-0012', "\xF0\x82\x82\xAC", 'An overlong encoding of a character that has a short one, which is how two different byte strings become the same name.'),
            $enc('byt-0013', "notes\xFF.txt", 'A byte that begins no valid sequence.'),
            $enc('byt-0014', "\xC0\xAE\xC0\xAE/secret.txt", 'Overlong `..` as raw bytes rather than percent-encoded — the same attack as enc-0007, one decoding layer further in.'),
        ];
    }

    /**
     * Names that render as something other than what they are.
     *
     * @return list<EscapeAttempt>
     */
    private static function deception(): array
    {
        $inv = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::Deception, Refusal::InvisibleCharacter, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        $hom = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::Deception, Refusal::SeparatorHomoglyph, Unguarded::Confuses, Unguarded::Confuses, $note,
        );

        return [
            $inv('dec-0001', "\u{202E}txt.exe", 'A right-to-left override. Displays as `exe.txt` in every listing, every editor tab and every review UI. Trojan Source, applied to a filename.'),
            $inv('dec-0002', "report\u{202E}fdp.txt", 'The same trick mid-name, which reads as `report.pdf`.'),
            $inv('dec-0003', "\u{200E}notes.txt", 'A left-to-right mark: invisible, and enough to make two listings that look identical be different files.'),
            $inv('dec-0004', "\u{200F}notes.txt", 'The right-to-left mark.'),
            $inv('dec-0005', "\u{2066}notes\u{2069}.txt", 'Directional isolates, the modern replacement for the override characters and rarely on anyone\'s deny list.'),
            $inv('dec-0006', "\u{061C}notes.txt", 'The Arabic letter mark.'),
            $inv('dec-0007', "\u{202A}notes.txt", 'A left-to-right embedding.'),
            $inv('dec-0008', "\u{202D}notes.txt", 'A left-to-right override.'),
            $inv('dec-0009', "\u{200B}notes.txt", 'A zero-width space. Not a bidi character at all, and exactly as invisible.'),
            $inv('dec-0010', "\u{FEFF}notes.txt", 'A byte-order mark used as a filename character, which several tools strip and several do not.'),
            $inv('dec-0011', "\u{00AD}notes.txt", 'A soft hyphen: renders as nothing, or as a hyphen, depending on where it is line-wrapped.'),
            $hom('dec-0012', "reports\u{FF0F}secret.txt", 'A fullwidth solidus. Not a separator to any filesystem, so this is ONE file whose name reads as a path — a listing a human scans as two directory levels.'),
            $hom('dec-0013', "reports\u{2215}secret.txt", 'The division slash.'),
            $hom('dec-0014', "reports\u{2044}secret.txt", 'The fraction slash.'),
            $hom('dec-0015', "reports\u{FF3C}secret.txt", 'The fullwidth reverse solidus.'),
        ];
    }

    /**
     * @return list<EscapeAttempt>
     */
    private static function lengths(): array
    {
        return [
            new EscapeAttempt(
                'len-0001', str_repeat('a', 300), Hazard::Length, Refusal::SegmentTooLong,
                Unguarded::Confuses, Unguarded::Confuses,
                'A single component past the 255-byte limit both ext4 and NTFS enforce. Refused with a code rather than left to surface as an errno from three layers down.',
            ),
            new EscapeAttempt(
                'len-0002', implode('/', array_fill(0, 40, str_repeat('b', 40))), Hazard::Length, Refusal::TooLong,
                Unguarded::Confuses, Unguarded::Confuses,
                'Every component legal, the whole path not. Refused above the configured budget; note this is a SEPARATE limit from the Windows MAX_PATH check, which depends on where the disk root is and so cannot live in a guard that never touches the filesystem.',
            ),
        ];
    }

    /**
     * @return list<EscapeAttempt>
     */
    private static function emptyPaths(): array
    {
        $c = fn (string $id, string $path, string $note): EscapeAttempt => new EscapeAttempt(
            $id, $path, Hazard::EmptyPath, Refusal::EmptyPath, Unguarded::Harmless, Unguarded::Harmless, $note,
        );

        return [
            $c('emp-0001', '', 'The empty string. Harmless, and refused, because `write("", $content)` means the workspace directory itself and there is no version of that a caller wanted.'),
            $c('emp-0002', '.', 'The current directory.'),
            $c('emp-0003', './', 'With a separator.'),
            $c('emp-0004', './.', 'Nothing, twice.'),
            $c('emp-0005', '././', 'Nothing, twice, with separators — the case a normaliser that only strips a leading `./` gets wrong.'),
        ];
    }

    /**
     * Safe input, refused anyway. In the corpus so the cost is stated.
     *
     * @return list<EscapeAttempt>
     */
    private static function strictness(): array
    {
        return [
            new EscapeAttempt(
                'str-0001', 'docs/../report.md', Hazard::Strictness, Refusal::Traversal,
                Unguarded::Harmless, Unguarded::Harmless,
                'Resolves inside the workspace and is completely safe. Refused because resolving `..` correctly means being right every time, and refusing it means being right once. An agent has no reason to double back through a directory it just named.',
            ),
            new EscapeAttempt(
                'str-0002', 'a/b/../c.txt', Hazard::Strictness, Refusal::Traversal,
                Unguarded::Harmless, Unguarded::Harmless,
                'The same trade, one level down.',
            ),
            new EscapeAttempt(
                'str-0003', 'draft~1.txt', Hazard::Strictness, Refusal::ShortNameAlias,
                Unguarded::Harmless, Unguarded::Harmless,
                'A perfectly reasonable filename that is indistinguishable from an 8.3 alias, because an 8.3 alias is exactly this shape. The cost of refusing the shape, named rather than discovered.',
            ),
            new EscapeAttempt(
                'str-0004', '..cache/notes.txt', Hazard::Strictness, Refusal::Traversal,
                Unguarded::Harmless, Unguarded::Harmless,
                'A directory whose name merely STARTS with two dots. Safe, and refused, for the same reason: "the segment begins with .." is a shape, and a guard that refuses shapes never has to be clever.',
            ),
        ];
    }
}
