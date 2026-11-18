<?php

/*
 * Runs the tests in testing/tests/ and reports any that fail, throw an error, or raise a warning or deprecation.
 * Each *Test.php file in that folder is picked up automatically, and is given $smoke (the runner) and $dir (a temporary
 * directory, deleted afterwards).
 *
 * Usage: php testing/main.php (or composer test). Set NFTABLES_TEST_ONLY to run only the tests whose name contains it.
 * Exits with 0 if everything passed, or 1 if anything failed.
 */

require_once(__DIR__ . '/../vendor/autoload.php');

use Programster\Nftables\Testing\SmokeTestRunner;

$testFiles = glob(__DIR__ . '/tests/*Test.php');

if ($testFiles === false)
{
    echo "Couldn't list the test files in " . __DIR__ . "/tests.\n";
    exit(1);
}

sort($testFiles);
$only = (string)getenv("NFTABLES_TEST_ONLY");
$smoke = new SmokeTestRunner($only);
$dir = sys_get_temp_dir() . "/nftables-smoke-" . bin2hex(random_bytes(8));
mkdir($dir, 0700);

foreach ($testFiles as $testFile)
{
    require $testFile;
}

// The tests only write files directly into $dir.
$leftoverFiles = glob("{$dir}/*");

if ($leftoverFiles === false)
{
    echo "Couldn't list the files in {$dir}, so it hasn't been deleted.\n";
}
else
{
    foreach ($leftoverFiles as $file)
    {
        unlink($file);
    }

    rmdir($dir);
}
// Accessors have no docblock, so this says what they hold.
/** @var string[] $failures */
$failures = $smoke->getFailures();

// Otherwise a name that matches nothing would pass without checking anything.
if ($only !== "" && $smoke->getNumPassed() === 0 && count($failures) === 0)
{
    $failures[] = "NFTABLES_TEST_ONLY: no test's name contains \"{$only}\", so nothing was run.";
}

// Where nft is known to be available (e.g. the Docker runs), a skipped nft test means something is wrong.
if (getenv("NFTABLES_TEST_REQUIRE_NFT") === "1" && count($smoke->getSkipped()) > 0)
{
    $failures[] = "NFTABLES_TEST_REQUIRE_NFT: tests were skipped, but nft should be available here.";
}

printf("PHP %s: %d passed, %d failed\n", PHP_VERSION, $smoke->getNumPassed(), count($failures));

foreach ($failures as $failure)
{
    echo "  FAIL {$failure}\n";
}

// So that a run where something wasn't available doesn't look like it checked everything.
/** @var string[] $skippedTests */
$skippedTests = $smoke->getSkipped();

foreach ($skippedTests as $skipped)
{
    echo "  SKIPPED {$skipped}\n";
}

exit(count($failures) === 0 ? 0 : 1);
