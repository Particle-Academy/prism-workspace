<?php

declare(strict_types=1);

use Tests\TestCase;

// Only the integration suite boots Laravel. The guard and the corpus are pure
// functions of a string, and 429 of the tests here are in that half — booting an
// application for each of them would spend most of the suite's time proving that
// Testbench works.
uses(TestCase::class)->in('Integration');
