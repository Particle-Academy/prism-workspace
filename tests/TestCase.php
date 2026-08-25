<?php

declare(strict_types=1);

namespace Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Prism\Workspace\PrismWorkspaceServiceProvider;

abstract class TestCase extends Orchestra
{
    /** The `local` disk root for this test. Real directories, on a real filesystem. */
    protected string $diskRoot;

    /**
     * The directory ABOVE the disk, which the corpus runner sweeps for strays.
     *
     * Deliberately deep and per-test: three levels above a workspace is
     * `<sandbox>`, so a sweep stays inside a directory this test owns instead of
     * walking the machine's temp directory.
     */
    protected string $sandbox;

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [PrismWorkspaceServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $this->sandbox = sys_get_temp_dir().DIRECTORY_SEPARATOR.'prism-workspace-tests'.DIRECTORY_SEPARATOR.bin2hex(random_bytes(8));
        $this->diskRoot = $this->sandbox.DIRECTORY_SEPARATOR.'disk';

        mkdir($this->diskRoot, 0777, true);

        // A real local disk rather than Storage::fake(). The whole subject of
        // this package is what a real filesystem does with a name — trailing
        // dots, device names, case folding, links — and a faked disk is a disk
        // with none of that in it.
        $app['config']->set('filesystems.disks.local', [
            'driver' => 'local',
            'root' => $this->diskRoot,
            'throw' => false,
        ]);

        $app['config']->set('workspace.disk', 'local');
        $app['config']->set('workspace.root', 'workspaces');
    }

    protected function tearDown(): void
    {
        $this->deleteDirectory($this->sandbox ?? '');

        parent::tearDown();
    }

    private function deleteDirectory(string $directory): void
    {
        if ($directory === '' || ! is_dir($directory)) {
            return;
        }

        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $directory.DIRECTORY_SEPARATOR.$entry;

            // is_link before is_dir: a link to a directory is a directory to
            // is_dir, and recursing through one would delete the target rather
            // than the link. Tests here create exactly that on purpose.
            if (is_link($path)) {
                @unlink($path) || @rmdir($path);

                continue;
            }

            is_dir($path) ? $this->deleteDirectory($path) : @unlink($path);
        }

        @rmdir($directory);
    }
}
