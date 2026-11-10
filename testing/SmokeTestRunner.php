<?php

namespace Programster\Nftables\Testing;

use Exception;
use Throwable;

/**
 * A small test runner for the tests in testing/tests/. Each test is a named callback, which fails if it throws
 * (including a failed check, such as assertSame()) or raises a warning, notice or deprecation.
 *
 * The checks throw an exception themselves, rather than using assert(), so they still check things when
 * zend.assertions is turned off.
 */
final class SmokeTestRunner
{
    private int $m_numPassed;

    /** @var string[] */
    private array $m_failures;

    /** @var string[] */
    private array $m_skipped;

    /** @var string[] - every warning raised so far, so run() can tell which ones its test raised. */
    private array $m_warnings;

    // Only the tests whose name contains this are run, or every test if it's empty.
    private string $m_only;


    /**
     * Create the runner, which reports every warning, notice and deprecation from here on as a failure of the test
     * that raised it.
     *
     * @param string $only - optionally, run only the tests whose name contains this. Defaults to running every test.
     */
    public function __construct(string $only = "")
    {
        $this->m_numPassed = 0;
        $this->m_failures = [];
        $this->m_skipped = [];
        $this->m_warnings = [];
        $this->m_only = $only;
        error_reporting(-1);

        $recordWarning = function (int $errorNumber, string $message, string $file, int $line) : bool {
            // Respect the @ operator, for code that deliberately suppresses a warning.
            if (error_reporting() & $errorNumber)
            {
                $this->m_warnings[] = "[E{$errorNumber}] {$message} @ " . basename($file) . ":{$line}";
            }

            return true;
        };

        set_error_handler($recordWarning);
    }


    /**
     * Run one test, recording it as failed if it throws, or raises any warnings or deprecations.
     *
     * @param string $label - the name of the test, shown if it fails.
     *
     * @param callable $test - the test to run.
     *
     * @return void
     */
    public function run(string $label, callable $test) : void
    {
        if ($this->m_only === "" || str_contains($label, $this->m_only))
        {
            $numWarningsBefore = count($this->m_warnings);
            $error = "";

            try
            {
                $test();
            }
            catch (Throwable $e)
            {
                $location = basename($e->getFile()) . ":" . $e->getLine();
                $error = get_class($e) . ": " . $e->getMessage() . " @ {$location}";
            }

            $newWarnings = array_slice($this->m_warnings, $numWarningsBefore);

            if ($error === "" && count($newWarnings) === 0)
            {
                $this->m_numPassed++;
            }
            else
            {
                $this->m_failures[] = trim("{$label}: {$error} " . implode(" | ", $newWarnings));
            }
        }
    }


    /**
     * Record tests as skipped, because something they need isn't available here, so they're reported rather than
     * looking as if they passed.
     *
     * @param string $label - what was skipped.
     *
     * @param string $reason - why, e.g. "nft isn't installed".
     *
     * @return void
     */
    public function skip(string $label, string $reason) : void
    {
        $this->m_skipped[] = "{$label} ({$reason})";
    }


    /**
     * Check that two values are identical (===), the same type, and for arrays, the same keys in the same order.
     *
     * @param mixed $expected - the value it should be.
     *
     * @param mixed $actual - the value being checked.
     *
     * @param string $what - what is being checked, to show if it fails.
     *
     * @return void
     *
     * @throws Exception - if they're not identical.
     */
    public static function assertSame(mixed $expected, mixed $actual, string $what) : void
    {
        if ($expected !== $actual)
        {
            $flags = JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR;
            $expectedJson = json_encode($expected, $flags);
            $actualJson = json_encode($actual, $flags);
            throw new Exception("{$what}: expected {$expectedJson}, but got {$actualJson}");
        }
    }


    /**
     * Check that a condition holds.
     *
     * @param bool $condition - the condition.
     *
     * @param string $what - what is being checked, to show if it fails.
     *
     * @return void
     *
     * @throws Exception - if it doesn't hold.
     */
    public static function assertTrue(bool $condition, string $what) : void
    {
        if (!$condition)
        {
            throw new Exception("{$what}: this wasn't the case");
        }
    }


    /**
     * Check that a list contains a value (compared with ===), e.g. that nft's listing contains a line.
     *
     * @param array $list - the list to look in.
     *
     * @param mixed $value - the value it should contain.
     *
     * @param string $what - what is being checked, to show if it fails.
     *
     * @return void
     *
     * @throws Exception - if it doesn't contain it.
     */
    public static function assertContains(array $list, mixed $value, string $what) : void
    {
        if (!in_array($value, $list, true))
        {
            $flags = JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR;
            $valueJson = json_encode($value, $flags);
            $listJson = json_encode(array_values($list), $flags);
            throw new Exception("{$what}: expected {$valueJson} in {$listJson}");
        }
    }


    /**
     * Check that a callback throws a specific type of exception.
     *
     * @param string $exceptionClass - the class (or interface) of exception that should be thrown.
     *
     * @param callable $callback - the code that should throw it.
     *
     * @param string $messageContains - optionally, text the exception's message must contain, for when the same
     * class of exception can be thrown for different reasons. Defaults to "", for any message.
     *
     * @return void
     *
     * @throws Throwable - if the callback throws a different exception, it's rethrown.
     *
     * @throws Exception - if the callback doesn't throw at all, or the message doesn't contain $messageContains.
     */
    public static function expectException(
        string $exceptionClass,
        callable $callback,
        string $messageContains = "",
    ) : void
    {
        $threwExpectedException = false;

        try
        {
            $callback();
        }
        catch (Throwable $e)
        {
            if (!($e instanceof $exceptionClass))
            {
                throw $e;
            }

            if (!str_contains($e->getMessage(), $messageContains))
            {
                $message = "Expected the message to contain \"{$messageContains}\", but it was: {$e->getMessage()}";
                throw new Exception($message);
            }

            $threwExpectedException = true;
        }

        if (!$threwExpectedException)
        {
            throw new Exception("Expected {$exceptionClass} to be thrown, but nothing was thrown.");
        }
    }


    # Accessors
    public function getNumPassed() : int { return $this->m_numPassed; }
    public function getFailures() : array { return $this->m_failures; }
    public function getSkipped() : array { return $this->m_skipped; }
}
