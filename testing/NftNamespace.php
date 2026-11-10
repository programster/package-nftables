<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use Programster\Nftables\Ruleset;
use RuntimeException;

/**
 * Runs real nft inside throwaway network namespaces ("unshare -rn"), which need no root and never touch the host's
 * rules. Every run gets a new, empty namespace.
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
     * Find an nft that can be run inside an unprivileged network namespace, where the network devices the flowtable
     * tests use can be created.
     *
     * @param string $dir - the directory to write ruleset files to.
     *
     * @return NftNamespace
     *
     * @throws RuntimeException - if nft or ip (from iproute2) isn't installed, or they can't be run in a namespace
     * (e.g. unprivileged user namespaces are turned off).
     */
    public static function create(string $dir) : NftNamespace
    {
        $nft = self::findNft();

        if ($nft === "")
        {
            throw new RuntimeException("nft isn't installed");
        }

        $check = escapeshellarg($nft) . " list ruleset && " . self::createDevices();
        self::runCommand(["unshare", "-rn", "sh", "-ec", $check]);
        return new NftNamespace($nft, $dir);
    }


    /**
     * Get the version of this machine's nft.
     *
     * @return string - e.g. "1.1.3", or "" if nft isn't installed.
     */
    public static function findNftablesVersion() : string
    {
        $nft = self::findNft();
        $version = "";

        if ($nft !== "" && preg_match('/v(\d+\.\d+\.\d+)/', self::runCommand([$nft, "--version"]), $match))
        {
            $version = $match[1];
        }

        return $version;
    }


    /**
     * Load a ruleset into an empty namespace, check nft kept all of it, and get nft's own listing of what was loaded.
     * The namespace has two network devices, eth0 and eth1 (a veth pair), for flowtables to use.
     *
     * @param Ruleset $ruleset - the ruleset.
     *
     * @return string[] - the lines of "nft list ruleset", with their indentation removed.
     *
     * @throws RuntimeException - if nft rejects the ruleset, with nft's error, or loads it but silently drops part of
     * it (e.g. a table's flags, a chain's hook, or a statement).
     */
    public function loadAndList(Ruleset $ruleset) : array
    {
        $file = $this->writeRulesetFile("ruleset-" . bin2hex(random_bytes(6)) . ".json", $ruleset);
        $nft = escapeshellarg($this->m_nft);
        $separator = "=== JSON ===";
        $devices = self::createDevices();
        $listings = "{$nft} list ruleset\necho '{$separator}'\n{$nft} --json list ruleset";
        $script = "{$devices}\n{$this->load($file)}\n{$listings}";
        [$listing, $json] = explode($separator, self::runCommand(["unshare", "-rn", "bash", "-ec", $script]));
        self::assertNothingDropped($ruleset->toArray()["nftables"], json_decode($json, true)["nftables"]);
        return array_map("trim", explode("\n", trim($listing)));
    }


    /**
     * Write a ruleset's JSON to a file.
     *
     * @param string $name - the name to give the file.
     *
     * @param Ruleset $ruleset - the ruleset to write.
     *
     * @return string - the path to the file.
     */
    public function writeRulesetFile(string $name, Ruleset $ruleset) : string
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
     * @return array<string, string[]> - each table that exists at the end ("family name"), sorted, with the comments
     * of the rules in it, in order.
     *
     * @throws RuntimeException - if any of the commands fail.
     */
    public function listTablesAfter(array $commands) : array
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
     * Check that nft kept everything it was given that it can silently drop: every table, chain, set, map, flowtable
     * and named object, tables' flags, chains' hooks, flowtables' devices, ct timeouts' policies, and every kind of
     * statement, including the statements in a set update. Matches aren't compared, as nft leaves out ones that a
     * later statement implies (e.g. meta l4proto tcp before reject with tcp reset).
     *
     * @param array $sent - the items in the ruleset that was loaded.
     *
     * @param array $listed - the items in nft's JSON listing of what it loaded.
     *
     * @return void
     *
     * @throws RuntimeException - if anything was dropped.
     */
    private static function assertNothingDropped(array $sent, array $listed) : void
    {
        $listedItems = [];
        $listedStatements = [];

        foreach ($listed as $item)
        {
            $kind = array_key_first($item);

            if ($kind === "rule")
            {
                foreach ($item["rule"]["expr"] as $statement)
                {
                    $listedStatements[self::describeStatement($statement)] = true;
                }
            }
            elseif ($kind !== "metainfo")
            {
                $listedItems[self::describeItem($item)] = $item[$kind];
            }
        }

        $dropped = [];

        foreach ($sent as $item)
        {
            $kind = array_key_first($item);

            if ($kind === "rule")
            {
                foreach ($item["rule"]["expr"] as $statement)
                {
                    $description = self::describeStatement($statement);
                    $isKept = ($description === "match" || isset($listedStatements[$description]));
                    $dropped[] = $isKept ? "" : "a {$description} statement";
                }
            }
            elseif (!in_array($kind, ["metainfo", "add", "delete", "flush"], true))
            {
                $description = self::describeItem($item);
                $dropped[] = self::findDroppedPart($description, $item[$kind], $listedItems[$description] ?? null);
            }
        }

        $dropped = array_values(array_unique(array_filter($dropped)));

        if (count($dropped) > 0)
        {
            throw new RuntimeException("nft loaded the ruleset, but silently dropped " . implode(", ", $dropped));
        }
    }


    /**
     * Find what part of an item nft dropped, if any.
     *
     * @param string $description - what the item is, e.g. "chain inet t input".
     *
     * @param array $sent - the item's definition, as it was loaded.
     *
     * @param array|null $listed - its definition in nft's listing, or null if it isn't listed.
     *
     * @return string - what was dropped, e.g. "the hook of chain inet t input", or "" for nothing.
     */
    private static function findDroppedPart(string $description, array $sent, ?array $listed) : string
    {
        $kind = explode(" ", $description)[0];
        $isCtTimeout = str_starts_with($description, "ct timeout ");
        $hasPolicy = (is_array($listed["policy"] ?? null) && count($listed["policy"]) > 0);

        return match (true) {
            $listed === null => $description,
            isset($sent["flags"]) && $kind === "table" && !isset($listed["flags"]) => "the flags of {$description}",
            isset($sent["hook"]) && $kind === "chain" && !isset($listed["hook"]) => "the hook of {$description}",
            $kind === "flowtable" && count((array)($listed["dev"] ?? [])) === 0 => "the devices of {$description}",
            $isCtTimeout && !$hasPolicy => "the policy of {$description}",
            default => "",
        };
    }


    /**
     * Describe a table, chain, set, map, flowtable or named object, as unique to it, e.g. "chain inet t input".
     *
     * @param array $item - the item's definition, e.g. ["chain" => [...]].
     *
     * @return string
     */
    private static function describeItem(array $item) : string
    {
        $kind = array_key_first($item);
        $definition = $item[$kind];
        $table = ($kind === "table") ? "" : " {$definition["table"]}";
        return "{$kind} {$definition["family"]}{$table} {$definition["name"]}";
    }


    /**
     * Describe a statement, by its kind, and whether a set update has statements, e.g. "set (with statements)".
     *
     * @param array $statement - the statement.
     *
     * @return string
     */
    private static function describeStatement(array $statement) : string
    {
        $kind = array_key_first($statement);
        $hasStatements = ($kind === "set" && isset($statement["set"]["stmt"]));
        return $hasStatements ? "set (with statements)" : $kind;
    }


    /**
     * Get the shell command that creates the network devices the flowtable tests use, in a namespace.
     *
     * @return string
     */
    private static function createDevices() : string
    {
        return "ip link add eth0 type veth peer name eth1";
    }


    /**
     * Find an nft that can be run.
     *
     * @return string - its path, or "" if nft isn't installed.
     */
    private static function findNft() : string
    {
        $nft = "";

        foreach (self::NFT_LOCATIONS as $location)
        {
            if ($nft === "" && is_executable($location))
            {
                $nft = $location;
            }
        }

        return $nft;
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
