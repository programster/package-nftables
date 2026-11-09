<?php

namespace Programster\Nftables\Testing;

use Programster\Nftables\NftablesRuleset;
use RuntimeException;

/**
 * Runs real nft inside throwaway network namespaces ("unshare -rn"), which need no root and never touch the host's
 * rules. Each call to runInFreshNamespace() gets a new, empty namespace.
 */
final readonly class NftNamespace
{
    private const NFT_LOCATIONS = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/usr/local/sbin/nft"];

    private string $m_nft;
    private string $m_dir;


    private function __construct(string $nft, string $dir)
    {
        $this->m_nft = $nft;
        $this->m_dir = $dir;
    }


    /**
     * Find an nft that can be run inside an unprivileged network namespace.
     *
     * @param string $dir - the directory to write ruleset files to.
     *
     * @return NftNamespace
     *
     * @throws RuntimeException - if nft isn't installed, or can't be run in a namespace (e.g. unprivileged user
     * namespaces are turned off).
     */
    public static function create(string $dir) : NftNamespace
    {
        $nft = "";

        foreach (self::NFT_LOCATIONS as $location)
        {
            if ($nft === "" && is_executable($location))
            {
                $nft = $location;
            }
        }

        if ($nft === "")
        {
            throw new RuntimeException("nft isn't installed");
        }

        self::runCommand(["unshare", "-rn", $nft, "list", "ruleset"]);
        return new NftNamespace($nft, $dir);
    }


    /**
     * Write a ruleset's JSON to a file.
     *
     * @param string $name - the name to give the file.
     *
     * @param NftablesRuleset $ruleset - the ruleset to write.
     *
     * @return string - the path to the file.
     */
    public function writeRulesetFile(string $name, NftablesRuleset $ruleset) : string
    {
        $path = "{$this->m_dir}/{$name}";
        file_put_contents($path, $ruleset->toJson());
        return $path;
    }


    /**
     * Get the shell command that loads a ruleset file.
     *
     * @param string $file - the path to the file.
     *
     * @return string
     */
    public function load(string $file) : string
    {
        return escapeshellarg($this->m_nft) . " --json --file " . escapeshellarg($file);
    }


    /**
     * Get the shell command that loads a ruleset file, and fails if it loads, for a file that nft should reject.
     *
     * @param string $file - the path to the file.
     *
     * @return string
     */
    public function loadExpectingFailure(string $file) : string
    {
        return "if {$this->load($file)} 2>/dev/null; then echo 'the file loaded' >&2; exit 1; fi";
    }


    /**
     * Get the shell command that creates a table this library knows nothing about, as fail2ban would.
     *
     * @return string
     */
    public function createForeignTable() : string
    {
        return escapeshellarg($this->m_nft) . " add table inet fail2ban";
    }


    /**
     * Run shell commands, one after the other, in a new, empty network namespace, stopping at the first that fails,
     * then list what is loaded.
     *
     * @param string[] $commands - the commands to run.
     *
     * @return array<string, string[]> - each table that exists at the end ("family name"), sorted, with the comments of
     * the rules in it, in order.
     *
     * @throws RuntimeException - if any of the commands fail.
     */
    public function runInFreshNamespace(array $commands) : array
    {
        $commands[] = escapeshellarg($this->m_nft) . " --json list ruleset";
        $output = self::runCommand(["unshare", "-rn", "bash", "-ec", implode("\n", $commands)]);
        $items = json_decode($output, true, 512, JSON_THROW_ON_ERROR)["nftables"];
        $tables = [];

        foreach ($items as $item)
        {
            if (isset($item["table"]))
            {
                $tables["{$item["table"]["family"]} {$item["table"]["name"]}"] = [];
            }
            elseif (isset($item["rule"]))
            {
                $tables["{$item["rule"]["family"]} {$item["rule"]["table"]}"][] = $item["rule"]["comment"] ?? "";
            }
        }

        ksort($tables);
        return $tables;
    }


    /**
     * Run a command directly (not through a shell).
     *
     * @param string[] $command - the program and its arguments.
     *
     * @return string - what it wrote to stdout.
     *
     * @throws RuntimeException - if it can't be run, or exits with a non-zero status.
     */
    private static function runCommand(array $command) : string
    {
        $pipes = [];
        $descriptors = [1 => ["pipe", "w"], 2 => ["pipe", "w"]];
        $process = @proc_open($command, $descriptors, $pipes);

        if ($process === false)
        {
            throw new RuntimeException("couldn't run {$command[0]}");
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        if ($exitCode !== 0)
        {
            throw new RuntimeException("{$command[0]} exited with {$exitCode}: " . trim($stderr));
        }

        return $stdout;
    }
}
