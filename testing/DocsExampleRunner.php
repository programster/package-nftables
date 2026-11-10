<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use Programster\Nftables\Ruleset;
use RuntimeException;

/**
 * Turns a document's examples into a script and runs it, so the docs can't drift from what the code (and nft) does:
 *
 * - its php code blocks run in order, as one script, with a use statement for every class in the package added.
 *
 * - an nft code block (a listing from "nft list ruleset") is checked against nft's own listing of the $ruleset the
 * code before it built: each of its lines, other than closing braces, must be in nft's listing. The ruleset is only
 * loaded if this machine's nft is at least the ruleset's target, and its wording only compared on the nft the docs'
 * listings come from (1.1.3), as other versions word some things differently.
 *
 * - a php block whose first line is "// Throws SomeException" must throw that exception.
 *
 * - file_put_contents() calls are captured instead of writing anywhere.
 *
 * - $smoke is a SmokeTestRunner, as in a test file, for the examples of writing a test.
 */
final readonly class DocsExampleRunner
{
    private string $m_repoDir;
    private string $m_dir;


    /**
     * Create a runner.
     *
     * @param string $repoDir - the root of the repository.
     *
     * @param string $dir - a temporary directory for the generated scripts.
     */
    public function __construct(string $repoDir, string $dir)
    {
        $this->m_repoDir = $repoDir;
        $this->m_dir = $dir;
    }


    /**
     * Run a document's examples.
     *
     * @param string $document - the path to the markdown document.
     *
     * @param bool $checkWithNft - whether to load the rulesets into nft, and check the nft blocks against them.
     *
     * @return void
     *
     * @throws RuntimeException - if an example fails, with what went wrong.
     */
    public function run(string $document, bool $checkWithNft) : void
    {
        $script = $this->m_dir . "/" . basename($document, ".md") . "-" . bin2hex(random_bytes(4)) . ".php";
        file_put_contents($script, $this->createScript((string)file_get_contents($document), $checkWithNft));
        $output = [];
        $exitCode = 0;
        exec(escapeshellarg(PHP_BINARY) . " " . escapeshellarg($script) . " 2>&1", $output, $exitCode);

        if ($exitCode !== 0 || implode("\n", $output) !== "")
        {
            throw new RuntimeException(basename($document) . ": " . implode(" | ", $output));
        }
    }


    /**
     * Check that every line of a listing from the docs is in nft's listing of a ruleset. Called from the generated
     * scripts, which it ends with an error if the check fails.
     *
     * @param Ruleset $ruleset - the ruleset the example built.
     *
     * @param string[] $expectedLines - the lines in the docs' listing.
     *
     * @param int $blockNumber - which block the listing is in the document, for the message.
     *
     * @return void
     */
    public static function check(Ruleset $ruleset, array $expectedLines, int $blockNumber) : void
    {
        $target = TestTarget::detect();
        $canLoad = $target->hasNftablesAtLeast($ruleset->getTarget()->getNftablesVersion());
        $listing = $canLoad ? NftNamespace::create(sys_get_temp_dir())->loadAndList($ruleset) : [];
        $toCompare = ($canLoad && TestTarget::isDocsVersion()) ? $expectedLines : [];

        foreach ($toCompare as $expectedLine)
        {
            if ($expectedLine !== "}" && !in_array($expectedLine, $listing, true))
            {
                $listed = implode(" / ", $listing);
                echo "block {$blockNumber}: nft didn't list \"{$expectedLine}\". It listed: {$listed}";
                exit(1);
            }
        }
    }


    /**
     * Create the script that runs a document's examples.
     *
     * @param string $markdown - the document.
     *
     * @param bool $checkWithNft - whether to check the nft blocks with nft.
     *
     * @return string - the PHP script.
     */
    private function createScript(string $markdown, bool $checkWithNft) : string
    {
        $uses = $this->findPackageClasses();
        $body = [];
        $blockNumber = 0;
        preg_match_all('/```(php|nft)\n(.*?)```/s', $markdown, $blocks, PREG_SET_ORDER);

        foreach ($blocks as [, $language, $code])
        {
            $blockNumber++;

            if ($language === "php")
            {
                $body[] = $this->convertPhpBlock($code, $blockNumber, $uses);
            }
            elseif ($checkWithNft)
            {
                $lines = array_values(array_filter(array_map("trim", explode("\n", $code))));
                $expected = var_export($lines, true);
                $body[] = "\\" . self::class . "::check(\$ruleset, {$expected}, {$blockNumber});";
            }
        }

        $useStatements = [];

        foreach (array_unique($uses) as $class)
        {
            $useStatements[] = "use {$class};";
        }

        // The examples' file_put_contents() calls are pointed at this instead, and any warning fails the example.
        $header = [
            "<?php",
            "declare(strict_types=1);",
            "require " . var_export($this->m_repoDir . "/vendor/autoload.php", true) . ";",
            ...$useStatements,
            "use Programster\\Nftables\\Testing\\SmokeTestRunner;",
            // For the examples of writing a test, which test files are given.
            "\$smoke = new SmokeTestRunner();",
            "function file_put_contents_example(string \$path, string \$data) : int { return strlen(\$data); }",
            "\$throwOnWarning = function (int \$number, string \$text) : bool { throw new ErrorException(\$text); };",
            "set_error_handler(\$throwOnWarning);",
        ];

        return implode("\n", [...$header, ...$body]) . "\n";
    }


    /**
     * Convert a php block for the script: take out its use statements (they all go at the top), capture
     * file_put_contents(), and wrap it in a check if it's meant to throw.
     *
     * @param string $code - the block's code.
     *
     * @param int $blockNumber - which block it is in the document, for messages.
     *
     * @param string[] $uses - the classes to add use statements for, which the block's are added to.
     *
     * @return string
     */
    private function convertPhpBlock(string $code, int $blockNumber, array &$uses) : string
    {
        $lines = [];

        foreach (explode("\n", $code) as $line)
        {
            if (preg_match('/^use ([^;]+);$/', $line, $match))
            {
                $uses[] = $match[1];
            }
            else
            {
                $lines[] = str_replace("file_put_contents(", "file_put_contents_example(", $line);
            }
        }

        $converted = implode("\n", $lines);

        if (preg_match('/^\/\/ Throws (\w+)/', trim($code), $match))
        {
            $exception = $match[1];
            $check = "if (!\$threw) { echo \"block {$blockNumber} didn't throw {$exception}\"; exit(1); }";
            $catch = "catch ({$exception} \$e) { \$threw = true; }";
            $converted = "\$threw = false;\ntry {\n{$converted}\n} {$catch}\n{$check}";
        }

        return $converted;
    }


    /**
     * Get the full name of every class, interface and enum in the package.
     *
     * @return string[]
     */
    private function findPackageClasses() : array
    {
        $classes = [];

        foreach (glob($this->m_repoDir . "/src/{,*/}*.php", GLOB_BRACE) as $file)
        {
            preg_match('/^namespace ([^;]+);/m', (string)file_get_contents($file), $namespace);
            $classes[] = $namespace[1] . "\\" . basename($file, ".php");
        }

        return $classes;
    }
}
