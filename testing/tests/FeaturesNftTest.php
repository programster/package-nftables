<?php

/*
 * Loads every feature into real nft, checks nft kept all of it, and (on nft 1.1+, which words its listings as these
 * expect) checks nft's own listing of it, so each one is known to be accepted by nft and to mean what it should. The
 * features that need a newer nft than the oldest supported are tested in CompatibilityTest instead. Each test runs in
 * its own throwaway network namespace ("unshare -rn"), which needs no root and never touches the host's rules. They're
 * skipped (and reported as skipped) where nft or unprivileged user namespaces aren't available. These are run by
 * testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\AnonymousMap;
use Programster\Nftables\AnonymousVerdictMap;
use Programster\Nftables\BaseChain;
use Programster\Nftables\Chain;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\AddressType;
use Programster\Nftables\Enums\BinaryOperator;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\CtDirection;
use Programster\Nftables\Enums\CtHelperType;
use Programster\Nftables\Enums\CtKey;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\FibFlag;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Enums\IcmpRejectCode;
use Programster\Nftables\Enums\Icmpv6RejectCode;
use Programster\Nftables\Enums\IcmpxRejectCode;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\Ipv6ExtensionHeader;
use Programster\Nftables\Enums\Ipv6ExtensionHeaderField;
use Programster\Nftables\Enums\LimitMatch;
use Programster\Nftables\Enums\LimitPeriod;
use Programster\Nftables\Enums\LimitUnit;
use Programster\Nftables\Enums\LogFlag;
use Programster\Nftables\Enums\LogLevel;
use Programster\Nftables\Enums\MatchMode;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\NatFlag;
use Programster\Nftables\Enums\NumgenMode;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\PayloadBase;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\QueueFailMode;
use Programster\Nftables\Enums\QuotaMatch;
use Programster\Nftables\Enums\QuotaUnit;
use Programster\Nftables\Enums\RtKey;
use Programster\Nftables\Enums\SetFlag;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\SetUpdateOperation;
use Programster\Nftables\Enums\TcpOption;
use Programster\Nftables\Enums\TcpOptionField;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Expressions\BinaryOperationExpression;
use Programster\Nftables\Expressions\ConcatExpression;
use Programster\Nftables\Expressions\CtExpression;
use Programster\Nftables\Expressions\ExthdrExpression;
use Programster\Nftables\Expressions\FibExpression;
use Programster\Nftables\Expressions\HashExpression;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\NumgenExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Expressions\PrefixExpression;
use Programster\Nftables\Expressions\RangeExpression;
use Programster\Nftables\Expressions\RawExpression;
use Programster\Nftables\Expressions\RtExpression;
use Programster\Nftables\Expressions\SetExpression;
use Programster\Nftables\Expressions\TcpOptionExpression;
use Programster\Nftables\MapElement;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\NamedMap;
use Programster\Nftables\NamedSet;
use Programster\Nftables\NamedVerdictMap;
use Programster\Nftables\Objects\CtHelper;
use Programster\Nftables\Objects\NamedCounter;
use Programster\Nftables\Objects\NamedLimit;
use Programster\Nftables\Objects\NamedQuota;
use Programster\Nftables\PortRange;
use Programster\Nftables\PortSet;
use Programster\Nftables\RegularChain;
use Programster\Nftables\Rule;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Statements\CounterStatement;
use Programster\Nftables\Statements\DnatStatement;
use Programster\Nftables\Statements\GotoStatement;
use Programster\Nftables\Statements\JumpStatement;
use Programster\Nftables\Statements\LimitStatement;
use Programster\Nftables\Statements\LogStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\MasqueradeStatement;
use Programster\Nftables\Statements\MatchStatement;
use Programster\Nftables\Statements\NotrackStatement;
use Programster\Nftables\Statements\QueueStatement;
use Programster\Nftables\Statements\QuotaStatement;
use Programster\Nftables\Statements\RawStatement;
use Programster\Nftables\Statements\RedirectStatement;
use Programster\Nftables\Statements\RejectStatement;
use Programster\Nftables\Statements\SetUpdateStatement;
use Programster\Nftables\Statements\SnatStatement;
use Programster\Nftables\Statements\Statement;
use Programster\Nftables\Table;
use Programster\Nftables\VerdictMapElement;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\NftNamespace;
use Programster\Nftables\Testing\SmokeTestRunner;
use Programster\Nftables\Testing\TestTarget;

/** @var SmokeTestRunner $smoke */
/** @var string $dir - a temporary directory for the tests to use, which is deleted afterwards. */

$registerFeatureTests = function (NftNamespace $nft) use ($smoke) : void {
    // Load a ruleset (which checks nothing was dropped), and check that each expected line is in nft's listing of it.
    // A line can be a list of the ways different nft versions word it.
    $assertLoadsAs = function (Ruleset $ruleset, string|array ...$expectedLines) use ($nft) : void {
        $listing = $nft->loadAndList($ruleset);

        foreach (TestTarget::hasCurrentListings() ? $expectedLines : [] as $expectedLine)
        {
            $wordings = is_array($expectedLine) ? $expectedLine : [$expectedLine];
            $listed = array_intersect($wordings, $listing);
            $what = "nft listed " . json_encode($wordings) . " (in " . json_encode($listing) . ")";
            SmokeTestRunner::assertTrue(count($listed) > 0, $what);
        }
    };

    // Load some rules, and check nft lists each of them as expected.
    $assertRulesLoadAs = function (array $expectedLines, Rule ...$rules) use ($assertLoadsAs) : void {
        $ruleset = new Ruleset(TestTarget::detect());
        $ruleset->addRule(...$rules);
        $assertLoadsAs($ruleset, ...$expectedLines);
    };

    // Short ways to create a rule, and a chain with an accept policy, to keep the tests readable.
    $rule = function (Chain $chain, Statement ...$statements) : Rule {
        return Rule::create($chain, ...$statements);
    };

    $chain = function (
        string $name,
        Table $table,
        ChainType $type,
        ChainHook $hook,
        int|Priority $priority,
        string $device = "",
    ) : BaseChain {
        return new BaseChain($name, $table, $type, $hook, $priority, Policy::ACCEPT, $device);
    };

    $ipTable = Fixtures::createTable("t", Family::IP);
    $ip6Table = Fixtures::createTable("t", Family::IP6);
    $inetTable = Fixtures::createTable("t", Family::INET);
    $input = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::INPUT);
    $input6 = Fixtures::createBaseChain($ip6Table, ChainType::FILTER, ChainHook::INPUT);
    $inetInput = Fixtures::createBaseChain($inetTable, ChainType::FILTER, ChainHook::INPUT);
    $forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
    $prerouting = Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::PREROUTING);
    $postrouting = Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::POSTROUTING);
    $inetPrerouting = Fixtures::createBaseChain($inetTable, ChainType::NAT, ChainHook::PREROUTING);
    $prerouting6 = Fixtures::createBaseChain($ip6Table, ChainType::NAT, ChainHook::PREROUTING);
    $isTcp = MatchFactory::createTransportProtocol(Protocol::TCP);

    # Tables and chains

    $testTablesAndChains = function () use ($assertLoadsAs, $chain, $ipTable) : void {
        $other = new Table("other", Family::INET);
        $ruleset = new Ruleset(TestTarget::detect());
        $ruleset->addChain(new BaseChain("in", $other, ChainType::FILTER, ChainHook::INPUT, 10, Policy::DROP));
        $ruleset->addChain($chain("raw", $ipTable, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW));
        $ruleset->addChain($chain("rt", $ipTable, ChainType::ROUTE, ChainHook::OUTPUT, Priority::MANGLE));
        $ruleset->addChain($chain("sn", $ipTable, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT));
        $ruleset->addChain($chain("dn", $ipTable, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT));
        $ruleset->addChain($chain("sec", $ipTable, ChainType::FILTER, ChainHook::INPUT, Priority::SECURITY));
        $ruleset->addChain($chain("custom", $ipTable, ChainType::FILTER, ChainHook::INPUT, -7));
        $ruleset->addChain(new RegularChain("plain", $ipTable));

        // nft quietly turns a base chain it can't read into a regular one, so check every one kept its hook.
        $assertLoadsAs(
            $ruleset,
            "table inet other {",
            "type filter hook input priority filter + 10; policy drop;",
            "type filter hook prerouting priority raw; policy accept;",
            "type route hook output priority mangle; policy accept;",
            "type nat hook postrouting priority srcnat; policy accept;",
            "type nat hook prerouting priority dstnat; policy accept;",
            "type filter hook input priority security; policy accept;",
            "type filter hook input priority filter - 7; policy accept;",
            "chain plain {",
        );
    };

    $smoke->run("nft: tables, base chains (every type and priority) and regular chains load", $testTablesAndChains);

    $testOtherFamilies = function () use ($assertLoadsAs, $chain) : void {
        $bridge = new Table("br", Family::BRIDGE);
        $arp = new Table("arp", Family::ARP);
        $ruleset = new Ruleset(TestTarget::detect());
        $ruleset->addChain($chain("f", $bridge, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER));
        $ruleset->addChain($chain("o", $bridge, ChainType::FILTER, ChainHook::OUTPUT, Priority::OUT));
        $ruleset->addChain($chain("i", $arp, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER));

        $assertLoadsAs(
            $ruleset,
            "type filter hook forward priority filter; policy accept;",
            "type filter hook output priority out; policy accept;",
            "type filter hook input priority filter; policy accept;",
        );
    };

    $smoke->run("nft: bridge and arp chains load", $testOtherFamilies);

    # Verdicts and simple statements

    $testVerdicts = function () use ($assertRulesLoadAs, $rule, $input, $ipTable) : void {
        $target = new RegularChain("target", $ipTable);

        $rules = [
            $rule($input, new CounterStatement(), Verdict::ACCEPT),
            $rule($input, Verdict::DROP),
            $rule($input, Verdict::CONTINUE),
            $rule($input, Verdict::RETURN),
            $rule($input, new JumpStatement($target)),
            $rule($input, new GotoStatement($target)),
        ];

        $expected = ["counter packets 0 bytes 0 accept", "drop", "continue", "return", "jump target", "goto target"];
        $assertRulesLoadAs([...$expected, "chain target {"], ...$rules);
    };

    $smoke->run("nft: verdicts, jump, goto and counter load", $testVerdicts);

    $testLog = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $withFlags = new LogStatement("dropped: ", LogLevel::INFO, LogFlag::TCP_SEQUENCE, LogFlag::IP_OPTIONS);
        $withAll = new LogStatement("all: ", LogLevel::DEBUG, LogFlag::ALL, LogFlag::ALL);
        $rules = [$rule($input, new LogStatement()), $rule($input, $withFlags), $rule($input, $withAll)];

        $expected = [
            "log",
            'log prefix "dropped: " level info flags tcp sequence flags ip options',
            'log prefix "all: " level debug flags all',
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: log statements load", $testLog);

    $testLimit = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $within = new LimitStatement(10, LimitPeriod::SECOND, LimitMatch::WITHIN_LIMIT);
        $over = new LimitStatement(10, LimitPeriod::MINUTE, LimitMatch::OVER_LIMIT, 20);
        $bytes = new LimitStatement(2, LimitPeriod::SECOND, LimitMatch::WITHIN_LIMIT, 512, LimitUnit::KBYTES);
        $rules = [$rule($input, $within, Verdict::ACCEPT), $rule($input, $over, Verdict::DROP), $rule($input, $bytes)];

        $expected = [
            "limit rate 10/second burst 5 packets accept",
            "limit rate over 10/minute burst 20 packets drop",
            "limit rate 2 kbytes/second burst 512 kbytes",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: limit statements (within and over the limit, packets and bytes) load", $testLimit);

    $testReject = function () use ($assertRulesLoadAs, $rule, $input, $input6, $inetInput, $isTcp) : void {
        $rules = [
            $rule($input, RejectStatement::create()),
            $rule($input, $isTcp, RejectStatement::createTcpReset()),
            $rule($input, RejectStatement::createIcmp(IcmpRejectCode::HOST_PROHIBITED)),
            $rule($input6, RejectStatement::createIcmpv6(Icmpv6RejectCode::ADMIN_PROHIBITED)),
            $rule($inetInput, RejectStatement::createIcmpx(IcmpxRejectCode::NO_ROUTE)),
        ];

        $expected = [
            "reject",
            // nft leaves out the l4proto match, as the reject implies it.
            "reject with tcp reset",
            "reject with icmp host-prohibited",
            "reject with icmpv6 admin-prohibited",
            "reject with icmpx no-route",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: reject statements (every type) load", $testReject);

    $testNat = function () use ($assertRulesLoadAs, $rule, $prerouting, $postrouting, $isTcp) : void {
        $portRange = new PortRange(5000, 6000);
        $dnatToRange = DnatStatement::create("10.0.0.3", $portRange, NatFlag::RANDOM, NatFlag::PERSISTENT);
        $masqueradeToRange = new MasqueradeStatement(new PortRange(1024, 2048), NatFlag::FULLY_RANDOM);

        $rules = [
            $rule($prerouting, DnatStatement::create("10.0.0.1")),
            $rule($prerouting, $isTcp, DnatStatement::create("10.0.0.2", 8080)),
            $rule($prerouting, $isTcp, $dnatToRange),
            $rule($prerouting, $isTcp, new RedirectStatement(3128)),
            $rule($prerouting, new RedirectStatement()),
            $rule($postrouting, SnatStatement::create("203.0.113.1")),
            $rule($postrouting, new MasqueradeStatement()),
            $rule($postrouting, $isTcp, $masqueradeToRange),
        ];

        $expected = [
            "dnat to 10.0.0.1",
            "meta l4proto tcp dnat to 10.0.0.2:8080",
            "meta l4proto tcp dnat to 10.0.0.3:5000-6000 random,persistent",
            "meta l4proto tcp redirect to :3128",
            "redirect",
            "snat to 203.0.113.1",
            "masquerade",
            "meta l4proto tcp masquerade to :1024-2048 fully-random",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: dnat, snat, masquerade and redirect statements load", $testNat);

    $testNatIpv6AndInet = function () use ($assertRulesLoadAs, $rule, $prerouting6, $inetPrerouting, $isTcp) : void {
        $rules = [
            $rule($prerouting6, $isTcp, DnatStatement::create("fd00::1", 80)),
            $rule($inetPrerouting, DnatStatement::create("10.0.0.1")),
            $rule($inetPrerouting, DnatStatement::create("fd00::2")),
        ];

        $expected = ["meta l4proto tcp dnat to [fd00::1]:80", "dnat ip to 10.0.0.1", "dnat ip6 to fd00::2"];
        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: NAT to IPv6 addresses, and in inet tables, loads", $testNatIpv6AndInet);

    $testNotrackAndMangle = function () use ($assertRulesLoadAs, $rule, $chain, $ipTable) : void {
        $raw = $chain("raw", $ipTable, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW);

        $rules = [
            $rule($raw, new NotrackStatement()),
            $rule($raw, MangleStatement::createSetMetaMark(42)),
            $rule($raw, MangleStatement::createSetCtMark(0xFFFFFFFF)),
            $rule($raw, new MangleStatement(new MetaExpression(MetaKey::PRIORITY), 5)),
        ];

        $expected = ["notrack", "meta mark set 0x0000002a", "ct mark set 0xffffffff", "meta priority set 0:5"];
        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: notrack and mangle (meta mark, ct mark) statements load", $testNotrackAndMangle);

    $testQueue = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $rules = [
            $rule($input, QueueStatement::create(QueueFailMode::DROP)),
            $rule($input, QueueStatement::create(QueueFailMode::ACCEPT, 3)),
            $rule($input, QueueStatement::createSpread(QueueFailMode::DROP, 2, 5)),
            $rule($input, QueueStatement::createSpread(QueueFailMode::ACCEPT, 6, 9)),
        ];

        $expected = [
            "queue to 0",
            "queue flags bypass to 3",
            "queue flags fanout to 2-5",
            "queue flags bypass,fanout to 6-9",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: queue statements (both fail modes, one queue and spread) load", $testQueue);

    $testRawStatementAndExpression = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $quota = new RawStatement(["quota" => ["val" => 25, "val_unit" => "mbytes"]]);
        $fib = new RawExpression(["fib" => ["result" => "type", "flags" => ["daddr"]]]);
        $isLocal = new MatchStatement($fib, Operator::EQUALS, "local");
        $rules = [$rule($input, $quota), $rule($input, $isLocal, Verdict::ACCEPT)];
        $assertRulesLoadAs(["quota 25 mbytes", "fib daddr type local accept"], ...$rules);
    };

    $smoke->run("nft: raw statements and expressions load", $testRawStatementAndExpression);

    # Expressions and operators

    $testOperators = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
        $rules = [];
        $expected = [];

        foreach (Operator::cases() as $operator)
        {
            if ($operator !== Operator::IN)
            {
                $rules[] = $rule($input, new MatchStatement($dport, $operator, 1024), Verdict::ACCEPT);
                $shown = ($operator === Operator::EQUALS) ? "" : "{$operator->value} ";
                $expected[] = "tcp dport {$shown}1024 accept";
            }
        }

        $flags = PayloadExpression::create(PayloadField::TCP_FLAGS);
        $rules[] = $rule($input, new MatchStatement($flags, Operator::IN, "syn"), Verdict::ACCEPT);
        $expected[] = "tcp flags syn accept";
        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: every match operator loads", $testOperators);

    $testExpressions = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);
        $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
        $icmpType = PayloadExpression::create(PayloadField::ICMP_TYPE);
        $pairs = new SetExpression(new ConcatExpression("10.0.0.1", 22));
        $rawPort = PayloadExpression::createRaw(PayloadBase::TRANSPORT_LAYER, 16, 16);
        $ctSource = new CtExpression(CtKey::SADDR, CtDirection::ORIGINAL, IpVersion::IPV4);
        $maskedMark = new BinaryOperationExpression(BinaryOperator::AND, new MetaExpression(MetaKey::MARK), 0xFF);

        // Each pair is the left and right sides of a match.
        $matches = [
            [$dport, new SetExpression(22, 80)],
            [$dport, new RangeExpression(5000, 6000)],
            [$saddr, new PrefixExpression("10.0.0.0", 8)],
            [new ConcatExpression($saddr, $dport), $pairs],
            [$rawPort, 22],
            [$ctSource, "10.0.0.1"],
            [$maskedMark, 1],
            [$icmpType, "echo-request"],
        ];

        $rules = [];

        foreach ($matches as [$left, $right])
        {
            $rules[] = $rule($input, new MatchStatement($left, Operator::EQUALS, $right), Verdict::ACCEPT);
        }

        $expected = [
            "tcp dport { 22, 80 } accept",
            "tcp dport 5000-6000 accept",
            "ip saddr 10.0.0.0/8 accept",
            "ip saddr . tcp dport { 10.0.0.1 . 22 } accept",
            "th dport 22 accept",
            "ct original ip saddr 10.0.0.1 accept",
            "meta mark & 0x000000ff == 0x00000001 accept",
            "icmp type echo-request accept",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: payload, meta, ct, set, range, prefix, concat and bitwise expressions load", $testExpressions);

    # Named sets

    $testNamedSets = function () use ($assertRulesLoadAs, $rule, $input, $input6, $ipTable, $ip6Table) : void {
        $blocked = ["198.51.100.7", "203.0.113.0/24"];
        $blocklist = NamedSet::createAddressSet($ipTable, "blocklist", IpVersion::IPV4, ...$blocked);
        $blocklist6 = NamedSet::createAddressSet($ip6Table, "blocklist6", IpVersion::IPV6, "2001:db8::/32");
        $ports = NamedSet::createPortSet($ipTable, "ports", 22, new PortRange(8000, 8080));
        $pairType = new SetTypeCollection([SetType::IPV4_ADDR, SetType::INET_SERVICE]);
        $pairs = NamedSet::create($ipTable, "pairs", $pairType)->withElements(new ConcatExpression("10.0.0.1", 22));
        $expiring = NamedSet::create($ipTable, "expiring", SetType::IPV4_ADDR)->withElements("10.0.0.9");
        $expiring = $expiring->withTimeout(3600);
        $interfaces = NamedSet::create($ipTable, "trusted", SetType::IFNAME)->withElements("lo", "eth1");
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);
        $saddr6 = PayloadExpression::create(PayloadField::IP6_SADDR);
        $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
        $iifname = new MetaExpression(MetaKey::IIFNAME);

        $rules = [
            $rule($input, MatchFactory::createInSet($saddr, $blocklist), Verdict::DROP),
            $rule($input6, MatchFactory::createInSet($saddr6, $blocklist6), Verdict::DROP),
            $rule($input, MatchFactory::createInSet($dport, $ports, MatchMode::DOES_NOT_MATCH), Verdict::DROP),
            $rule($input, MatchFactory::createInSet(new ConcatExpression($saddr, $dport), $pairs), Verdict::ACCEPT),
            $rule($input, MatchFactory::createInSet($saddr, $expiring), Verdict::ACCEPT),
            $rule($input, MatchFactory::createInSet($iifname, $interfaces), Verdict::ACCEPT),
        ];

        $expected = [
            "set blocklist {",
            "elements = { 198.51.100.7, 203.0.113.0/24 }",
            "elements = { 2001:db8::/32 }",
            "elements = { 22, 8000-8080 }",
            "type ipv4_addr . inet_service",
            "elements = { 10.0.0.1 . 22 }",
            "timeout 1h",
            "type ifname",
            "ip saddr @blocklist drop",
            "ip6 saddr @blocklist6 drop",
            "tcp dport != @ports drop",
            "ip saddr . tcp dport @pairs accept",
            "ip saddr @expiring accept",
            "iifname @trusted accept",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: named sets (addresses, ports, concatenations, timeouts, names) load", $testNamedSets);

    # MatchFactory

    $testMatchFactory = function () use ($assertRulesLoadAs, $rule, $input, $inetInput) : void {
        $notMatch = MatchMode::DOES_NOT_MATCH;
        $established = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);
        $invalid = new ConnectionStateSet(ConnectionState::INVALID);

        $rules = [
            $rule($input, MatchFactory::createInputInterfaceName("lo"), Verdict::ACCEPT),
            $rule($input, MatchFactory::createInputInterfaceName("eth0", $notMatch), Verdict::DROP),
            $rule($input, MatchFactory::createOutputInterfaceName("eth1"), Verdict::ACCEPT),
            $rule($input, MatchFactory::createDestinationPorts(Protocol::UDP, new PortSet(53, 53, 123))),
            $rule($input, MatchFactory::createSourcePorts(Protocol::TCP, new PortRange(1, 1023), $notMatch)),
            $rule($input, MatchFactory::createSourceAddress("192.168.0.0/16", $notMatch), Verdict::DROP),
            $rule($input, MatchFactory::createDestinationAddress("10.0.0.1"), Verdict::ACCEPT),
            $rule($inetInput, MatchFactory::createSourceAddress("fd00::/8"), Verdict::ACCEPT),
            $rule($input, MatchFactory::createConnectionStates($established), Verdict::ACCEPT),
            $rule($input, MatchFactory::createConnectionStates($invalid, $notMatch), Verdict::ACCEPT),
            $rule($input, MatchFactory::createTransportProtocol(Protocol::SCTP), Verdict::ACCEPT),
            $rule($input, MatchFactory::createTcpSyn(), Verdict::ACCEPT),
        ];

        $expected = [
            'iifname "lo" accept',
            'iifname != "eth0" drop',
            'oifname "eth1" accept',
            "udp dport { 53, 123 }",
            "tcp sport != 1-1023",
            "ip saddr != 192.168.0.0/16 drop",
            "ip daddr 10.0.0.1 accept",
            "ip6 saddr fd00::/8 accept",
            "ct state established,related accept",
            "ct state != invalid accept",
            "meta l4proto sctp accept",
            "tcp flags & (fin | syn | rst | ack) == syn accept",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: every MatchFactory match loads, including negated and IPv6 ones", $testMatchFactory);

    # Existence checks, fib, IPv6 extension headers, TCP options and routing data

    $testFib = function () use ($assertRulesLoadAs, $rule, $chain, $ipTable, $input) : void {
        $prerouting = $chain("prefilter", $ipTable, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW);
        $localType = new FibExpression(FibResult::TYPE, FibFlag::DADDR);
        $outputName = new FibExpression(FibResult::OIFNAME, FibFlag::DADDR, FibFlag::MARK);
        $routed = MatchFactory::createExistence(new FibExpression(FibResult::OIF, FibFlag::DADDR), Existence::EXISTS);

        $rules = [
            RuleFactory::createReversePathFilter($prerouting),
            $rule($input, new MatchStatement($localType, Operator::EQUALS, AddressType::LOCAL), Verdict::ACCEPT),
            $rule($input, new MatchStatement($outputName, Operator::EQUALS, "lo"), Verdict::ACCEPT),
            $rule($input, $routed, Verdict::ACCEPT),
        ];

        $expected = [
            // nft 1.1.5 and later word this as a "check".
            ["fib saddr . iif oif missing drop", "fib saddr . iif check missing drop"],
            "fib daddr type local accept",
            'fib daddr . mark oifname "lo" accept',
            ["fib daddr oif exists accept", "fib daddr check exists accept"],
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: fib lookups, and the reverse path filter, load", $testFib);

    $testExtensionHeaders = function () use ($assertRulesLoadAs, $rule, $input6) : void {
        $rules = [];
        $expected = [];

        foreach (Ipv6ExtensionHeader::cases() as $header)
        {
            $exists = MatchFactory::createExistence(ExthdrExpression::create($header), Existence::EXISTS);
            $rules[] = $rule($input6, $exists, Verdict::DROP);
            $expected[] = "exthdr {$header->value} exists drop";
        }

        $fragmentHeader = ExthdrExpression::create(Ipv6ExtensionHeader::FRAGMENT);
        $isFragment = MatchFactory::createExistence($fragmentHeader, Existence::MISSING);
        $moreFragments = ExthdrExpression::createField(Ipv6ExtensionHeaderField::FRAG_MORE_FRAGMENTS);
        $routingType = ExthdrExpression::createField(Ipv6ExtensionHeaderField::RT_TYPE);
        $rules[] = $rule($input6, $isFragment, Verdict::ACCEPT);
        $rules[] = $rule($input6, new MatchStatement($moreFragments, Operator::EQUALS, 1), Verdict::DROP);
        $rules[] = $rule($input6, new MatchStatement($routingType, Operator::EQUALS, 0), Verdict::DROP);
        $fields = ["exthdr frag missing accept", "frag more-fragments 1 drop", "rt type 0 drop"];
        $assertRulesLoadAs([...$expected, ...$fields], ...$rules);
    };

    $smoke->run("nft: IPv6 extension header checks and fields load", $testExtensionHeaders);

    $testTcpOptions = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $rules = [];
        $expected = [];

        foreach (TcpOption::cases() as $option)
        {
            $exists = MatchFactory::createExistence(TcpOptionExpression::create($option), Existence::EXISTS);
            $rules[] = $rule($input, $exists, Verdict::ACCEPT);
            $expected[] = "tcp option {$option->value} exists accept";
        }

        $size = TcpOptionExpression::createField(TcpOptionField::MAXSEG_SIZE);
        $window = TcpOptionExpression::createField(TcpOptionField::WINDOW_COUNT);
        $sackBlock = TcpOptionExpression::createField(TcpOptionField::SACK2_LEFT);
        $sizeIsSmall = new MatchStatement($size, Operator::LESS_THAN, 536);
        $windowCount = new MatchStatement($window, Operator::GREATER_THAN, 14);
        $sackBlockIsOne = new MatchStatement($sackBlock, Operator::EQUALS, 1);
        $rules[] = $rule($input, $sizeIsSmall, Verdict::DROP);
        $rules[] = $rule($input, $windowCount, Verdict::DROP);
        $rules[] = $rule($input, $sackBlockIsOne, Verdict::DROP);
        $fields = [
            "tcp option maxseg size < 536 drop",
            "tcp option window count > 14 drop",
            "tcp option sack2 left 1 drop",
        ];

        $assertRulesLoadAs([...$expected, ...$fields], ...$rules);
    };

    $smoke->run("nft: TCP option checks and fields load", $testTcpOptions);

    $testMssClamp = function () use ($assertRulesLoadAs, $rule, $chain, $forward, $inetTable) : void {
        $inetForward = $chain("forward", $inetTable, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER);
        $mtu = new MatchStatement(new RtExpression(RtKey::MTU), Operator::GREATER_THAN, 1400);

        $rules = [
            RuleFactory::createMssClamp($forward),
            RuleFactory::createMssClamp($inetForward),
            $rule($forward, MatchFactory::createTransportProtocol(Protocol::TCP), $mtu, Verdict::ACCEPT),
        ];

        $expected = ["tcp flags syn tcp option maxseg size set rt mtu", "meta l4proto tcp rt mtu > 1400 accept"];
        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: MSS clamping, and routing data, load", $testMssClamp);

    # Maps and verdict maps

    $natChains = [$prerouting, $postrouting];

    $testMaps = function () use ($assertRulesLoadAs, $rule, $ipTable, $natChains, $input, $isTcp) : void {
        [$prerouting, $postrouting] = $natChains;
        $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);
        $addresses = NamedMap::create($ipTable, "addresses", SetType::INET_SERVICE, SetType::IPV4_ADDR);
        $addresses = $addresses->withElements(new MapElement(2222, "10.0.0.2"), new MapElement(8080, "10.0.0.3"));
        $ports = NamedMap::create($ipTable, "ports", SetType::INET_SERVICE, SetType::INET_SERVICE);
        $ports = $ports->withElements(new MapElement(2222, 22), new MapElement(8080, 80));
        $ranges = NamedMap::create($ipTable, "ranges", SetType::INET_SERVICE, SetType::IPV4_ADDR, SetFlag::INTERVAL);
        $ranges = $ranges->withElements(new MapElement(new PortRange(5000, 5100), "10.0.0.4"));
        $marks = NamedMap::create($ipTable, "marks", SetType::IPV4_ADDR, SetType::MARK);
        $marks = $marks->withElements(new MapElement("10.0.0.1", 5));
        $public = NamedMap::create($ipTable, "public", SetType::IPV4_ADDR, SetType::IPV4_ADDR);
        $public = $public->withElements(new MapElement("10.0.0.2", "203.0.113.2"));
        $spread = new AnonymousMap(new MapElement(0, "10.0.0.5"), new MapElement(1, "10.0.0.6"));
        $turn = new NumgenExpression(NumgenMode::INCREMENTAL, 2);
        $toAddress = $addresses->lookUp($dport);
        $toAddressAndPort = DnatStatement::createFromMap(IpVersion::IPV4, $toAddress, $ports->lookUp($dport));
        $toRange = DnatStatement::createFromMap(IpVersion::IPV4, $ranges->lookUp($dport));
        $toPublic = SnatStatement::createFromMap(IpVersion::IPV4, $public->lookUp($saddr));
        $setMark = new MangleStatement(new MetaExpression(MetaKey::MARK), $marks->lookUp($saddr));

        $rules = [
            $rule($prerouting, $isTcp, $toAddressAndPort),
            $rule($prerouting, $isTcp, $toRange),
            $rule($prerouting, DnatStatement::createFromMap(IpVersion::IPV4, $spread->lookUp($turn))),
            $rule($postrouting, $toPublic),
            $rule($input, $setMark),
        ];

        $expected = [
            "map addresses {",
            "type inet_service : ipv4_addr",
            // nft lists elements over several lines once the line gets long.
            "elements = { 2222 : 10.0.0.2,",
            "8080 : 10.0.0.3 }",
            "type inet_service : inet_service",
            "elements = { 5000-5100 : 10.0.0.4 }",
            "type ipv4_addr : mark",
            "elements = { 10.0.0.1 : 0x00000005 }",
            // nft leaves out the l4proto match, as the tcp dport lookup implies it.
            "dnat to tcp dport map @addresses:tcp dport map @ports",
            "dnat to tcp dport map @ranges",
            "dnat to numgen inc mod 2 map { 0 : 10.0.0.5, 1 : 10.0.0.6 }",
            "snat to ip saddr map @public",
            "meta mark set ip saddr map @marks",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: named and anonymous maps load, for NAT and mangle statements", $testMaps);

    $testVerdictMaps = function () use ($assertRulesLoadAs, $rule, $ipTable, $input) : void {
        $web = new RegularChain("web", $ipTable);
        $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);

        $elements = [
            new VerdictMapElement(22, Verdict::ACCEPT),
            new VerdictMapElement(23, Verdict::DROP),
            new VerdictMapElement(80, new JumpStatement($web)),
            new VerdictMapElement(81, new GotoStatement($web)),
        ];

        $services = NamedVerdictMap::create($ipTable, "services", SetType::INET_SERVICE)->withElements(...$elements);
        $pairType = new SetTypeCollection([SetType::IPV4_ADDR, SetType::INET_SERVICE]);
        $pair = new VerdictMapElement(new ConcatExpression("10.0.0.1", 22), Verdict::ACCEPT);
        $pairs = NamedVerdictMap::create($ipTable, "pairs", $pairType)->withElements($pair);
        $ranges = NamedVerdictMap::create($ipTable, "ranges", SetType::IPV4_ADDR, SetFlag::INTERVAL);
        $ranges = $ranges->withElements(new VerdictMapElement(new PrefixExpression("10.0.0.0", 8), Verdict::RETURN));
        $anonymous = new AnonymousVerdictMap(new VerdictMapElement(8080, Verdict::ACCEPT));

        $rules = [
            $rule($input, $services->lookUp($dport)),
            $rule($input, $pairs->lookUp(new ConcatExpression($saddr, $dport))),
            $rule($input, $ranges->lookUp($saddr)),
            $rule($input, $anonymous->lookUp($dport)),
        ];

        $expected = [
            "chain web {",
            "type inet_service : verdict",
            "elements = { 22 : accept,",
            "80 : jump web,",
            "81 : goto web }",
            "type ipv4_addr . inet_service : verdict",
            "elements = { 10.0.0.1 . 22 : accept }",
            "elements = { 10.0.0.0/8 : return }",
            "tcp dport vmap @services",
            "ip saddr . tcp dport vmap @pairs",
            "ip saddr vmap @ranges",
            "tcp dport vmap { 8080 : accept }",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: named and anonymous verdict maps load, with the chains they jump to", $testVerdictMaps);

    # Quotas and named objects

    $testQuotas = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $over = new QuotaStatement(25, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA);
        $within = new QuotaStatement(1, QuotaUnit::KBYTES, QuotaMatch::WITHIN_QUOTA, 512);
        $bytes = new QuotaStatement(5000, QuotaUnit::BYTES, QuotaMatch::WITHIN_QUOTA);
        $rules = [$rule($input, $over, Verdict::DROP), $rule($input, $within, Verdict::ACCEPT), $rule($input, $bytes)];
        $expected = ["quota over 25 mbytes drop", "quota 1 kbytes used 512 bytes accept", "quota 5000 bytes"];
        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: quota statements (within and over, with bytes used) load", $testQuotas);

    $testNamedObjects = function () use ($assertRulesLoadAs, $rule, $ipTable, $input) : void {
        $counter = new NamedCounter("guest1", $ipTable);
        $overQuota = new QuotaStatement(10, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA);
        $quota = new NamedQuota("guest1", $ipTable, $overQuota);
        $limit = new NamedLimit("ssh", $ipTable, new LimitStatement(10, LimitPeriod::MINUTE, LimitMatch::OVER_LIMIT));
        $withinLimit = new LimitStatement(2, LimitPeriod::SECOND, LimitMatch::WITHIN_LIMIT, 512, LimitUnit::KBYTES);
        $bytesLimit = new NamedLimit("bytes", $ipTable, $withinLimit);
        $partlyUsed = new QuotaStatement(1, QuotaUnit::KBYTES, QuotaMatch::WITHIN_QUOTA, 5);
        $withinQuota = new NamedQuota("used", $ipTable, $partlyUsed);

        $rules = [
            $rule($input, $counter->createStatement()),
            $rule($input, $quota->createStatement(), Verdict::DROP),
            $rule($input, $limit->createStatement(), Verdict::DROP),
            $rule($input, $bytesLimit->createStatement(), Verdict::ACCEPT),
            $rule($input, $withinQuota->createStatement(), Verdict::ACCEPT),
        ];

        $expected = [
            "counter guest1 {",
            "quota guest1 {",
            "over 10 mbytes",
            "limit ssh {",
            "rate over 10/minute",
            "rate 2 kbytes/second burst 512 kbytes",
            "1 kbytes used 5 bytes",
            'counter name "guest1"',
            'quota name "guest1" drop',
            'limit name "ssh" drop',
            'limit name "bytes" accept',
            'quota name "used" accept',
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: named counters, quotas and limits load", $testNamedObjects);

    $testCtHelpers = function () use ($assertRulesLoadAs, $rule, $chain, $ipTable, $inetTable) : void {
        $prerouting = $chain("helpers", $ipTable, ChainType::FILTER, ChainHook::PREROUTING, Priority::FILTER);
        $inetPrerouting = $chain("helpers", $inetTable, ChainType::FILTER, ChainHook::PREROUTING, Priority::FILTER);
        $rules = [];
        $expected = [];

        foreach (CtHelperType::cases() as $type)
        {
            $helper = new CtHelper(strtolower($type->name), $ipTable, $type);
            $port = MatchFactory::createDestinationPorts($type->getProtocol(), 1000 + count($rules));
            $rules[] = $rule($prerouting, $port, $helper->createStatement());
            $protocol = $type->getProtocol()->value;
            $expected[] = "type \"{$type->getHelperName()}\" protocol {$protocol}";
            $expected[] = "{$protocol} dport " . (999 + count($rules)) . " ct helper set \"{$helper->getName()}\"";
        }

        $inetHelper = new CtHelper("ftp", $inetTable, CtHelperType::FTP);
        $toFtp = MatchFactory::createDestinationPorts(Protocol::TCP, 21);
        $rules[] = $rule($inetPrerouting, $toFtp, $inetHelper->createStatement());
        $assertRulesLoadAs([...$expected, "l3proto inet"], ...$rules);
    };

    $smoke->run("nft: ct helpers (every type, in ip and inet tables) load", $testCtHelpers);

    # Dynamic sets (meters), numgen and hashes

    $testSetUpdates = function () use ($assertRulesLoadAs, $rule, $ipTable, $input) : void {
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);
        $knocked = NamedSet::create($ipTable, "knocked", SetType::IPV4_ADDR)->withTimeout(30)->withSize(1000);
        $pairType = new SetTypeCollection([SetType::IPV4_ADDR, SetType::INET_SERVICE]);
        $pairs = NamedSet::create($ipTable, "pairs", $pairType)->withTimeout(60)->withSize(10);
        // Deleting doesn't need a size or timeout, as it can't fill the set.
        $permanent = NamedSet::create($ipTable, "permanent", SetType::IPV4_ADDR);
        $pair = new ConcatExpression($saddr, PayloadExpression::create(PayloadField::TCP_DPORT));

        $rules = [
            $rule($input, new SetUpdateStatement(SetUpdateOperation::ADD, $knocked, $saddr)),
            $rule($input, new SetUpdateStatement(SetUpdateOperation::UPDATE, $knocked, $saddr)),
            $rule($input, new SetUpdateStatement(SetUpdateOperation::DELETE, $knocked, $saddr)),
            $rule($input, new SetUpdateStatement(SetUpdateOperation::ADD, $pairs, $pair)),
            $rule($input, new SetUpdateStatement(SetUpdateOperation::DELETE, $permanent, $saddr)),
        ];

        $expected = [
            "size 1000",
            "add @knocked { ip saddr }",
            "update @knocked { ip saddr }",
            "delete @knocked { ip saddr }",
            "add @pairs { ip saddr . tcp dport }",
            "delete @permanent { ip saddr }",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: set updates (add, update and delete) load", $testSetUpdates);

    $testNumgenAndHashes = function () use ($assertRulesLoadAs, $rule, $input) : void {
        $mark = new MetaExpression(MetaKey::MARK);
        $saddr = PayloadExpression::create(PayloadField::IP_SADDR);
        $pair = new ConcatExpression($saddr, PayloadExpression::create(PayloadField::TCP_DPORT));

        $values = [
            new NumgenExpression(NumgenMode::INCREMENTAL, 2, 1),
            new NumgenExpression(NumgenMode::RANDOM, 3),
            HashExpression::createJhash($saddr, 4, 2, 1),
            HashExpression::createJhash($pair, 4),
            HashExpression::createSymhash(4, 3),
        ];

        $rules = [];

        foreach ($values as $value)
        {
            $rules[] = $rule($input, new MangleStatement($mark, $value));
        }

        $expected = [
            "meta mark set numgen inc mod 2 offset 1",
            "meta mark set numgen random mod 3",
            "meta mark set jhash ip saddr mod 4 seed 0x1 offset 2",
            "meta mark set jhash ip saddr . tcp dport mod 4",
            "meta mark set symhash mod 4 offset 3",
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: numgen, jhash and symhash expressions load", $testNumgenAndHashes);

    # RuleFactory

    $testRuleFactory = function () use ($assertRulesLoadAs, $input, $forward, $prerouting, $postrouting) : void {
        $established = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);
        $new = new ConnectionStateSet(ConnectionState::NEW);
        $range5000 = new PortRange(5000, 5100);
        $range6000 = new PortRange(6000, 6100);
        $syn = "tcp flags & (fin | syn | rst | ack) == syn";
        $network = "198.51.100.0/24";

        $rules = [
            RuleFactory::createAcceptInterface($input, "lo"),
            RuleFactory::createAcceptInterface($input, "eth0", $established),
            RuleFactory::createAcceptPort($input, "eth0", new PortSet(80, 443), sourceAddress: $network),
            RuleFactory::createAcceptPort($input, "eth0", 51820, Protocol::UDP, destinationAddress: "203.0.113.1"),
            RuleFactory::createPortForward($prerouting, "eth0", 8443, "10.14.0.10", 443),
            RuleFactory::createPortForward($prerouting, "eth0", $range5000, "10.14.0.11", sourceAddress: $network),
            RuleFactory::createPortForward($prerouting, "eth0", $range6000, "10.14.0.12", $range6000, Protocol::UDP),
            RuleFactory::createForward($forward, "eth0", "eth1", $new, destinationPorts: 443, requireTcpSyn: true),
            RuleFactory::createForward($forward, "eth1", "eth0", $established, sourceAddress: "10.14.0.10"),
            RuleFactory::createMasquerade($postrouting, "eth0"),
        ];

        $expected = [
            'iifname "lo" accept',
            'iifname "eth0" ct state established,related accept',
            'iifname "eth0" tcp dport { 80, 443 } ip saddr 198.51.100.0/24 accept',
            'iifname "eth0" udp dport 51820 ip daddr 203.0.113.1 accept',
            'iifname "eth0" tcp dport 8443 dnat to 10.14.0.10:443',
            'iifname "eth0" tcp dport 5000-5100 ip saddr 198.51.100.0/24 dnat to 10.14.0.11',
            'iifname "eth0" udp dport 6000-6100 dnat to 10.14.0.12:6000-6100',
            'iifname "eth0" oifname "eth1" tcp dport 443 ct state new ' . $syn . ' accept',
            'iifname "eth1" oifname "eth0" ip saddr 10.14.0.10 ct state established,related accept',
            'oifname "eth0" masquerade',
        ];

        $assertRulesLoadAs($expected, ...$rules);
    };

    $smoke->run("nft: every RuleFactory rule loads, and ends in a verdict", $testRuleFactory);
};

try
{
    $registerFeatureTests(NftNamespace::create($dir));
}
catch (RuntimeException $e)
{
    // Only create() can throw here, as $smoke->run() catches anything a test throws.
    $smoke->skip("every feature loaded into real nft", $e->getMessage());
}
