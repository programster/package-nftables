<?php

/*
 * Checks the features that need a newer nft (or kernel) than the oldest supported, on whichever target the tests are
 * running on (see TestTarget). For each one:
 *
 * - if the target meets its requirement, it must load into nft completely.
 *
 * - if not, a Ruleset for the target must refuse it, and (where it's nft that's too old, rather than the kernel, which
 *   Docker can't vary) loading it into this nft anyway must fail, or drop part of it, which proves the requirement is
 *   real. testing/run-all-targets.sh runs these on every supported target.
 *
 * The requirements are written out again here, rather than read from Compatibility, so that each checks the other.
 * These are run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\AnonymousMap;
use Programster\Nftables\BaseChain;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\CtTimeoutState;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\LimitMatch;
use Programster\Nftables\Enums\LimitPeriod;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\OsfKey;
use Programster\Nftables\Enums\OsfTtlCheck;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\SctpChunk;
use Programster\Nftables\Enums\SctpChunkField;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\SetUpdateOperation;
use Programster\Nftables\Enums\SynproxyFlag;
use Programster\Nftables\Enums\TableFlag;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;
use Programster\Nftables\Expressions\ConcatExpression;
use Programster\Nftables\Expressions\OsfExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Expressions\SctpChunkExpression;
use Programster\Nftables\Flowtable;
use Programster\Nftables\MapElement;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\NamedMap;
use Programster\Nftables\NamedSet;
use Programster\Nftables\Objects\CtTimeout;
use Programster\Nftables\Objects\CtTimeoutPolicy;
use Programster\Nftables\Objects\NamedSynproxy;
use Programster\Nftables\Objects\Secmark;
use Programster\Nftables\Rule;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Statements\CounterStatement;
use Programster\Nftables\Statements\DnatStatement;
use Programster\Nftables\Statements\LimitStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\MatchStatement;
use Programster\Nftables\Statements\SetUpdateStatement;
use Programster\Nftables\Statements\SynproxyStatement;
use Programster\Nftables\Statements\TproxyStatement;
use Programster\Nftables\Table;
use Programster\Nftables\Testing\NftNamespace;
use Programster\Nftables\Testing\SmokeTestRunner;
use Programster\Nftables\Testing\TestTarget;

/** @var SmokeTestRunner $smoke */
/** @var string $dir - a temporary directory for the tests to use, which is deleted afterwards. */

$createDormantTable = function (NftablesTarget $target) : Ruleset {
    $table = new Table("dormant", Family::INET, TableFlag::DORMANT);
    $ruleset = new Ruleset($target);
    $input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);
    $ruleset->addChain($input);
    return $ruleset;
};

// Each is a chain on a hook that needs a device, in a family.
$createDeviceChain = function (Family $family, ChainHook $hook) : Closure {
    $create = function (NftablesTarget $target) use ($family, $hook) : Ruleset {
        $table = new Table("devices", $family);
        $ruleset = new Ruleset($target);
        $chain = new BaseChain("chain", $table, ChainType::FILTER, $hook, Priority::FILTER, Policy::ACCEPT, "lo");
        $ruleset->addChain($chain);
        return $ruleset;
    };

    return $create;
};

// Each creates a ruleset of rules in a chain, from a function that's given the chain's table, and returns the
// statements of each rule.
$createRules = function (Family $family, ChainHook $hook, int|Priority $priority, Closure $createStatements) : Closure {
    $create = function (NftablesTarget $target) use ($family, $hook, $priority, $createStatements) : Ruleset {
        $type = ($hook === ChainHook::PREROUTING && $family === Family::IP) ? ChainType::NAT : ChainType::FILTER;
        $table = new Table("t", $family);
        $chain = new BaseChain("chain", $table, $type, $hook, $priority, Policy::ACCEPT);
        $ruleset = new Ruleset($target);

        foreach ($createStatements($table) as $statements)
        {
            $ruleset->addRule(Rule::create($chain, ...$statements));
        }

        return $ruleset;
    };

    return $create;
};

// Each creates rules in a nat chain on the prerouting hook, in an ip table.
$createNatRules = function (Closure $createStatements) use ($createRules) : Closure {
    return $createRules(Family::IP, ChainHook::PREROUTING, Priority::DSTNAT, $createStatements);
};

// Each creates rules in a filter chain, in an inet table.
$createFilterRules = function (
    ChainHook $hook,
    int|Priority $priority,
    Closure $createStatements,
) use ($createRules) : Closure {
    return $createRules(Family::INET, $hook, $priority, $createStatements);
};

$isTcp = MatchFactory::createTransportProtocol(Protocol::TCP);
$toSsh = MatchFactory::createDestinationPorts(Protocol::TCP, 22);
$dport = PayloadExpression::create(PayloadField::TCP_DPORT);
$saddr = PayloadExpression::create(PayloadField::IP_SADDR);
$guestAndPort = new ConcatExpression("10.0.0.2", 22);
$invalidOrUntracked = new ConnectionStateSet(ConnectionState::INVALID, ConnectionState::UNTRACKED);
$isInvalidOrUntracked = MatchFactory::createConnectionStates($invalidOrUntracked);
$synproxy = new SynproxyStatement(1460, 7, SynproxyFlag::TIMESTAMP, SynproxyFlag::SACK_PERMITTED);

$createFlowtable = function (NftablesTarget $target) : Ruleset {
    $table = new Table("t", Family::INET);
    $forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, 0, Policy::ACCEPT);
    $flowtable = new Flowtable("fastpath", $table, Priority::FILTER, "eth0", "eth1");
    $ruleset = new Ruleset($target);
    $ruleset->addRule(RuleFactory::createFlowOffload($forward, $flowtable));
    return $ruleset;
};

$createMapOfConcatenations = function (Table $table) use ($isTcp, $dport, $guestAndPort) : array {
    $valueType = new SetTypeCollection([SetType::IPV4_ADDR, SetType::INET_SERVICE]);
    $forwards = NamedMap::create($table, "forwards", SetType::INET_SERVICE, $valueType);
    $forwards = $forwards->withElements(new MapElement(2222, $guestAndPort));
    return [[$isTcp, DnatStatement::createFromMap(IpVersion::IPV4, $forwards->lookUp($dport))]];
};

$createAnonymousMapOfConcatenations = function (Table $table) use ($isTcp, $dport, $guestAndPort) : array {
    $forwards = new AnonymousMap(new MapElement(2222, $guestAndPort));
    return [[$isTcp, DnatStatement::createFromMap(IpVersion::IPV4, $forwards->lookUp($dport))]];
};

$createSetUpdateStatements = function (Table $table) use ($saddr) : array {
    $flood = NamedSet::create($table, "flood", SetType::IPV4_ADDR)->withTimeout(60)->withSize(1000);
    $overLimit = new LimitStatement(10, LimitPeriod::SECOND, LimitMatch::OVER_LIMIT);
    $add = new SetUpdateStatement(SetUpdateOperation::ADD, $flood, $saddr, new CounterStatement(), $overLimit);
    return [[$add, Verdict::DROP]];
};

$createCtTimeout = function (Table $table) use ($toSsh) : array {
    // The close timeout isn't the kernel's default (10 seconds), which nft would leave out of its listing.
    $established = new CtTimeoutPolicy(CtTimeoutState::TCP_ESTABLISHED, 7200);
    $timeout = new CtTimeout("long", $table, $established, new CtTimeoutPolicy(CtTimeoutState::TCP_CLOSE, 20));
    return [[$toSsh, $timeout->createStatement()]];
};

$createNamedSynproxy = function (Table $table) use ($isInvalidOrUntracked, $synproxy) : array {
    $named = new NamedSynproxy("web", $table, $synproxy);
    return [[$isInvalidOrUntracked, $named->createStatement()]];
};

$createSynproxy = function (Table $table) use ($isInvalidOrUntracked, $synproxy) : array {
    return [[$isInvalidOrUntracked, $synproxy]];
};

$createTproxy = function (Table $table) use ($isTcp) : array {
    $toAddress = TproxyStatement::createToAddress("127.0.0.1", 3128);
    $toPort = TproxyStatement::createToPort(IpVersion::IPV6, 3129);
    return [[$isTcp, MangleStatement::createSetMetaMark(1), $toAddress], [$isTcp, $toPort]];
};

$createOsf = function (Table $table) : array {
    $name = new MatchStatement(new OsfExpression(OsfKey::NAME, OsfTtlCheck::LOOSE), Operator::EQUALS, "Linux");
    $version = new MatchStatement(new OsfExpression(OsfKey::VERSION), Operator::EQUALS, "Linux:4.20");
    return [[$name, Verdict::ACCEPT], [$version, Verdict::ACCEPT]];
};

$createSecmark = function (Table $table) use ($toSsh) : array {
    // A context the security module knows is needed. "unconfined" is AppArmor's, which Debian and Ubuntu use.
    $secmark = new Secmark("ssh", $table, "unconfined");
    return [[$toSsh, $secmark->createStatement()]];
};

$createSctpChunks = function (Table $table) : array {
    $init = MatchFactory::createExistence(SctpChunkExpression::create(SctpChunk::INIT), Existence::EXISTS);
    $tsn = SctpChunkExpression::createField(SctpChunk::DATA, SctpChunkField::TSN);
    return [[$init, Verdict::ACCEPT], [new MatchStatement($tsn, Operator::EQUALS, 5), Verdict::ACCEPT]];
};

// Each is a description, the oldest nft and kernel ("" for any) it needs, any targets that have it although their nft
// or kernel is older, a function that builds a ruleset that uses it, and lines nft's listing of it should have
// (checked where the listings are worded as these expect). A line can be a list of the ways different nft versions
// word it.
$rhel8 = [NftablesTarget::ROCKY_8, NftablesTarget::ALMA_8, NftablesTarget::RHEL_8];
$rhel9 = [NftablesTarget::ROCKY_9, NftablesTarget::ALMA_9, NftablesTarget::RHEL_9];
$input = ChainHook::INPUT;
$filter = Priority::FILTER;
$features = [];
$features[] = ["the dormant table flag", "1.1.3", "", $rhel9, $createDormantTable, ["flags dormant"]];
$features[] = ["a netdev ingress chain", "1.0.6", "", [], $createDeviceChain(Family::NETDEV, ChainHook::INGRESS), []];
$features[] = ["a netdev egress chain", "1.0.6", "5.16", [], $createDeviceChain(Family::NETDEV, ChainHook::EGRESS), []];
$features[] = ["an inet ingress chain", "1.0.6", "", [], $createDeviceChain(Family::INET, ChainHook::INGRESS), []];

// nft 1.1.5 and later quote the devices.
$devices = ["devices = { eth0, eth1 }", 'devices = { "eth0", "eth1" }'];
$flowtableLines = ["hook ingress priority filter", $devices, "meta l4proto { tcp, udp } flow add @fastpath"];
$features[] = ["a flowtable", "1.0.6", "", [], $createFlowtable, $flowtableLines];

$features[] = [
    "a named map of concatenations",
    "1.1.3",
    "",
    $rhel9,
    $createNatRules($createMapOfConcatenations),
    ["elements = { 2222 : 10.0.0.2 . 22 }", "dnat ip to tcp dport map @forwards"],
];

$features[] = [
    "an anonymous map of concatenations",
    "1.0.2",
    "",
    [],
    $createNatRules($createAnonymousMapOfConcatenations),
    ["dnat ip to tcp dport map { 2222 : 10.0.0.2 . 22 }"],
];

$features[] = [
    "a set update with statements",
    "1.0.6",
    "",
    [],
    $createFilterRules($input, $filter, $createSetUpdateStatements),
    ["add @flood { ip saddr counter limit rate over 10/second burst 5 packets } drop"],
];

$features[] = [
    "a ct timeout",
    "1.0.9",
    "4.19",
    [],
    $createFilterRules(ChainHook::PREROUTING, Priority::RAW, $createCtTimeout),
    ["policy = { established : 2h, close : 20s }", 'tcp dport 22 ct timeout set "long"'],
];

$features[] = [
    "a named synproxy",
    "1.1.3",
    "5.3",
    $rhel9,
    $createFilterRules($input, $filter, $createNamedSynproxy),
    ['ct state invalid,untracked synproxy name "web"'],
];

$features[] = [
    "a synproxy",
    "0.9.8",
    "5.3",
    [],
    $createFilterRules($input, $filter, $createSynproxy),
    ["ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm"],
];

$features[] = [
    "a transparent proxy",
    "0.9.8",
    "4.19",
    $rhel8,
    $createFilterRules(ChainHook::PREROUTING, Priority::MANGLE, $createTproxy),
    ["meta l4proto tcp meta mark set 0x00000001 tproxy ip to 127.0.0.1:3128", "meta l4proto tcp tproxy ip6 to :3129"],
];

$features[] = [
    "operating system fingerprinting",
    "0.9.8",
    "4.19",
    [],
    $createFilterRules($input, $filter, $createOsf),
    ['osf ttl loose name "Linux" accept', 'osf version "Linux:4.20" accept'],
];

$features[] = [
    "a security mark",
    "1.0.6",
    "",
    [],
    $createFilterRules($input, $filter, $createSecmark),
    ['tcp dport 22 meta secmark set "ssh"'],
];

$features[] = [
    "an SCTP chunk",
    "1.0.2",
    "5.14",
    $rhel8,
    $createFilterRules($input, $filter, $createSctpChunks),
    ["sctp chunk init exists accept", "sctp chunk data tsn 5 accept"],
];

$registerCompatibilityTests = function (NftNamespace $nft) use ($smoke, $features) : void {
    $target = TestTarget::detect();

    foreach ($features as [$description, $nftablesVersion, $kernelVersion, $alsoSupportedBy, $createRuleset, $lines])
    {
        $isBackported = in_array($target, $alsoSupportedBy, true);
        $hasNftables = $target->hasNftablesAtLeast($nftablesVersion) || $isBackported;
        $hasKernel = ($kernelVersion === "" || $target->hasKernelAtLeast($kernelVersion) || $isBackported);

        $testFeature = function () use ($nft, $target, $createRuleset, $hasNftables, $hasKernel, $lines) : void {
            if ($hasNftables && $hasKernel)
            {
                $listing = $nft->loadAndList($createRuleset($target));

                // A line can be a list of the ways different nft versions word it.
                foreach (TestTarget::hasCurrentListings() ? $lines : [] as $line)
                {
                    $wordings = is_array($line) ? $line : [$line];
                    $what = "nft listed " . json_encode($wordings) . " (in " . json_encode($listing) . ")";
                    SmokeTestRunner::assertTrue(count(array_intersect($wordings, $listing)) > 0, $what);
                }
            }
            else
            {
                $createForTarget = function () use ($createRuleset, $target) : void {
                    $createRuleset($target);
                };

                SmokeTestRunner::expectException(UnsupportedFeatureException::class, $createForTarget);

                if (!$hasNftables)
                {
                    $loadAnyway = function () use ($nft, $createRuleset) : void {
                        $nft->loadAndList($createRuleset(NftablesTarget::NFTABLES_1_1_6));
                    };

                    SmokeTestRunner::expectException(RuntimeException::class, $loadAnyway);
                }
            }
        };

        $expectation = match (true) {
            !$hasNftables => "is refused, as it needs nft {$nftablesVersion}",
            !$hasKernel => "is refused, as it needs kernel {$kernelVersion}",
            default => "loads",
        };

        $smoke->run("Compatibility: {$description} {$expectation} ({$target->getDescription()})", $testFeature);
    }
};

try
{
    $registerCompatibilityTests(NftNamespace::create($dir));
}
catch (RuntimeException $e)
{
    // Only create() can throw here, as $smoke->run() catches anything a test throws.
    $smoke->skip("the features that need a newer nft, loaded into real nft", $e->getMessage());
}
