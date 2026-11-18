<?php

/*
 * Tests the JSON structure Ruleset produces, without needing nft. RulesetNftTest.php checks that real nft accepts it.
 * These are run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Collections\Exceptions\UnsupportedOperationException;
use Programster\Nftables\Chains\BaseChain;
use Programster\Nftables\Chains\RegularChain;
use Programster\Nftables\Collections\EmptyChainCollection;
use Programster\Nftables\Collections\EmptyTableCollection;
use Programster\Nftables\Collections\RuleCollection;
use Programster\Nftables\Collections\SetFlagCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\TableFlag;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\ConflictException;
use Programster\Nftables\Exceptions\NftablesException;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Helpers\MatchFactory;
use Programster\Nftables\Helpers\RuleFactory;
use Programster\Nftables\Maps\NamedMap;
use Programster\Nftables\Maps\NamedVerdictMap;
use Programster\Nftables\Maps\VerdictMapElement;
use Programster\Nftables\Objects\NamedCounter;
use Programster\Nftables\Rules\Rule;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Sets\NamedSet;
use Programster\Nftables\Statements\JumpStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\MatchStatement;
use Programster\Nftables\Statements\SynproxyStatement;
use Programster\Nftables\Tables\EmptyTable;
use Programster\Nftables\Tables\Flowtable;
use Programster\Nftables\Tables\Table;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */

$metainfo = ["metainfo" => ["json_schema_version" => 1]];

$noRules = new RuleCollection();

// Matches packets whose source address is in a set, so a rule can bring the set into a ruleset.
$matchSource = function (NamedSet $set) : MatchStatement {
    return MatchFactory::createInSet(PayloadExpression::create(PayloadField::IP_SADDR), $set);
};

$testDefaultResetMode = function () use ($noRules) : void {
    $ruleset = new Ruleset($noRules);
    $mode = $ruleset->getResetMode();
    SmokeTestRunner::assertSame(RulesetResetMode::REPLACE_OWN_TABLES, $mode, "the default reset mode");
};

$smoke->run("Ruleset: the default reset mode replaces its own tables", $testDefaultResetMode);

$testDefaultTarget = function () use ($noRules) : void {
    $ruleset = new Ruleset($noRules);
    SmokeTestRunner::assertSame(NftablesTarget::NFTABLES_0_9_8, $ruleset->getTarget(), "the default target");
};

$smoke->run("Ruleset: the default target is the oldest supported nft", $testDefaultTarget);

$testRefusesForTarget = function () use ($noRules) : void {
    $createWithDormantTable = function () use ($noRules) : void {
        $chain = Fixtures::createEmptyInputChain(new Table("t1", Family::INET, TableFlag::DORMANT));
        new Ruleset($noRules, NftablesTarget::DEBIAN_12, emptyChains: new EmptyChainCollection($chain));
    };

    $message = "The dormant table flag needs nft 1.1.3 or later, but this ruleset is for Debian 12 (nft 1.0.6).";
    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $createWithDormantTable, $message);
};

$smoke->run("Ruleset: a feature its target can't load is refused", $testRefusesForTarget);

$testKernelRequirement = function () : void {
    $table = Fixtures::createTable("t");
    $synproxy = new RuleCollection(Rule::create(Fixtures::createInputChain($table), new SynproxyStatement(1460, 7)));

    // Rocky 8's nft (1.0.4) handles a synproxy, but its kernel (4.18) doesn't have one, even with Red Hat's backports.
    $createForRocky8 = function () use ($synproxy) : void {
        new Ruleset($synproxy, NftablesTarget::ROCKY_8);
    };

    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $createForRocky8, "needs kernel 5.3");
    new Ruleset($synproxy, NftablesTarget::NFTABLES_1_0_4);
    new Ruleset($synproxy, NftablesTarget::ROCKY_9);
};

$smoke->run("Ruleset: an OS target also checks its kernel, and a version target doesn't", $testKernelRequirement);

$testRuleUsingUnsupportedChain = function () : void {
    $netdev = new Table("n", Family::NETDEV);
    $ingress = new BaseChain("i", $netdev, ChainType::FILTER, ChainHook::INGRESS, 0, Policy::ACCEPT, "lo");

    $createRuleset = function () use ($ingress) : void {
        new Ruleset(new RuleCollection(Rule::create($ingress, Verdict::DROP)), NftablesTarget::UBUNTU_22_04);
    };

    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $createRuleset, "ingress or egress hook");
};

$smoke->run("Ruleset: a rule in a chain its target can't load is refused", $testRuleUsingUnsupportedChain);

$testTargets = function () : void {
    SmokeTestRunner::assertSame("1.0.6", NftablesTarget::DEBIAN_12->getNftablesVersion(), "Debian 12's nft");
    $ubuntu = NftablesTarget::UBUNTU_22_04->getDescription();
    SmokeTestRunner::assertSame("Ubuntu 22.04 (nft 1.0.2)", $ubuntu, "Ubuntu 22.04's description");
    SmokeTestRunner::assertSame("nft 1.1.5", NftablesTarget::NFTABLES_1_1_5->getDescription(), "the 1.1.5 case");
    SmokeTestRunner::assertTrue(NftablesTarget::ALMA_10->hasNftablesAtLeast("1.1.3"), "AlmaLinux 10 has nft 1.1.3+");
    SmokeTestRunner::assertTrue(!NftablesTarget::RHEL_8->hasNftablesAtLeast("1.0.6"), "RHEL 8 doesn't have nft 1.0.6");

    foreach (NftablesTarget::cases() as $target)
    {
        // Every case must be handled, and none can be older than the oldest supported.
        SmokeTestRunner::assertTrue($target->hasNftablesAtLeast("0.9.8"), "{$target->name} is supported");
    }
};

$smoke->run("NftablesTarget: versions, kernels and descriptions", $testTargets);

foreach (RulesetResetMode::cases() as $mode)
{
    $testMetainfoFirst = function () use ($mode, $metainfo) : void {
        $rule = Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")));
        $ruleset = new Ruleset(new RuleCollection($rule), resetMode: $mode);
        $first = $ruleset->toArray()["nftables"][0];
        SmokeTestRunner::assertSame($metainfo, $first, "the first item");
    };

    $smoke->run("Ruleset: the metainfo block comes first ({$mode->name})", $testMetainfoFirst);
}

$testReplaceOwnTables = function () use ($metainfo, $noRules) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = new Table("t2", Family::IP6);
    $emptyTables = new EmptyTableCollection(new EmptyTable("t1", Family::IP), new EmptyTable("t2", Family::IP6));
    $ruleset = new Ruleset($noRules, resetMode: RulesetResetMode::REPLACE_OWN_TABLES, emptyTables: $emptyTables);

    $expected = [
        $metainfo,
        ["add" => $table1->toIdentifierArray()],
        ["delete" => $table1->toIdentifierArray()],
        ["add" => $table2->toIdentifierArray()],
        ["delete" => $table2->toIdentifierArray()],
        $table1->toArray(),
        $table2->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
    SmokeTestRunner::assertTrue(!str_contains($ruleset->toJson(), '"flush"'), "the JSON has no flush");
};

$smoke->run("Ruleset: REPLACE_OWN_TABLES adds then deletes each table first", $testReplaceOwnTables);

$testFlushEntireRuleset = function () use ($metainfo, $noRules) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $emptyTables = new EmptyTableCollection(new EmptyTable("t1", Family::IP), new EmptyTable("t2", Family::IP));
    $ruleset = new Ruleset($noRules, resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET, emptyTables: $emptyTables);
    $expected = [$metainfo, ["flush" => ["ruleset" => null]], $table1->toArray(), $table2->toArray()];
    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("Ruleset: FLUSH_ENTIRE_RULESET flushes once and deletes no tables", $testFlushEntireRuleset);

$testFlushIsJsonNull = function () use ($noRules) : void {
    $ruleset = new Ruleset($noRules, resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $flush = json_decode($ruleset->toJson(), false, 512, JSON_THROW_ON_ERROR)->nftables[1]->flush;
    SmokeTestRunner::assertTrue(property_exists($flush, "ruleset"), "the flush has a ruleset key");
    SmokeTestRunner::assertSame(null, $flush->ruleset, "the flush's ruleset");
};

$smoke->run("Ruleset: the flush is encoded as JSON null", $testFlushIsJsonNull);

$testEmptyRuleset = function () use ($metainfo, $noRules) : void {
    $ruleset = new Ruleset($noRules);
    SmokeTestRunner::assertSame(["nftables" => [$metainfo]], $ruleset->toArray(), "the empty ruleset");
};

$smoke->run("Ruleset: an empty ruleset is just the metainfo block", $testEmptyRuleset);

$testOrdering = function () use ($metainfo, $matchSource) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $chain1 = Fixtures::createInputChain($table1);
    $chain2 = Fixtures::createInputChain($table2);
    $emptyChains = new EmptyChainCollection(Fixtures::createEmptyInputChain($table2));
    $set = NamedSet::createAddressSet($table1, "blocklist", IpVersion::IPV4, "10.0.0.1");
    $rule = Rule::create($chain1, $matchSource($set), Verdict::DROP);
    $mode = RulesetResetMode::FLUSH_ENTIRE_RULESET;
    $ruleset = new Ruleset(new RuleCollection($rule), resetMode: $mode, emptyChains: $emptyChains);

    $expected = [
        $metainfo,
        ["flush" => ["ruleset" => null]],
        $table1->toArray(),
        $table2->toArray(),
        $chain1->toArray(),
        $chain2->toArray(),
        $set->toArray(),
        $rule->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("Ruleset: tables come first, then chains, then sets, then rules", $testOrdering);

$testRuleAddsWhatItUses = function () : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);
    $target = new RegularChain("services", $table);
    $set = NamedSet::createAddressSet($table, "blocklist", IpVersion::IPV4, "10.0.0.1");
    $sourceAddress = PayloadExpression::create(PayloadField::IP_SADDR);
    $blockRule = Rule::create($chain, MatchFactory::createInSet($sourceAddress, $set), Verdict::DROP);
    $rules = new RuleCollection($blockRule, Rule::create($chain, new JumpStatement($target)));
    $ruleset = new Ruleset($rules, resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $expected = ["metainfo" => 1, "flush" => 1, "table" => 1, "chain" => 2, "set" => 1, "rule" => 2];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$smoke->run("Ruleset: a rule brings its chain, table, jump targets and sets", $testRuleAddsWhatItUses);

$testRuleOrder = function () : void {
    $table = Fixtures::createTable("t1");
    $chain1 = Fixtures::createInputChain($table);
    $chain2 = Fixtures::createChain("other", $table, Policy::ACCEPT);

    $rules = new RuleCollection(
        Fixtures::createAcceptRule($chain1, "first"),
        Fixtures::createAcceptRule($chain2, "second"),
        Fixtures::createAcceptRule($chain1, "third"),
        Fixtures::createAcceptRule($chain1, "fourth"),
    );

    $comments = Fixtures::getRuleComments(new Ruleset($rules));
    SmokeTestRunner::assertSame(["first", "second", "third", "fourth"], $comments, "the rules' order");
};

$smoke->run("Ruleset: rules keep the order they were given in", $testRuleOrder);

$testRuleAddsMapsFlowtablesAndObjects = function () : void {
    $table = Fixtures::createTable("t1");
    $input = Fixtures::createInputChain($table);
    $forward = Fixtures::createBaseChain($table, ChainType::FILTER, ChainHook::FORWARD);
    $web = new RegularChain("web", $table);
    $dport = PayloadExpression::create(PayloadField::TCP_DPORT);
    $services = NamedVerdictMap::create($table, "services", SetType::INET_SERVICE);
    $services = $services->withElements(new VerdictMapElement(80, new JumpStatement($web)));
    $marks = NamedMap::create($table, "marks", SetType::INET_SERVICE, SetType::MARK);
    $setMark = new MangleStatement(new MetaExpression(MetaKey::MARK), $marks->lookUp($dport));
    $counter = new NamedCounter("web", $table);
    $flowtable = new Flowtable("fastpath", $table, 0, "eth0", "eth1");

    $rules = new RuleCollection(
        Rule::create($input, $services->lookUp($dport)),
        Rule::create($input, $setMark),
        Rule::create($input, $counter->createStatement()),
        RuleFactory::createFlowOffload($forward, $flowtable),
    );

    // Flowtables need nft 1.0.6.
    $ruleset = new Ruleset($rules, NftablesTarget::DEBIAN_12, RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $kinds = [];

    foreach ($ruleset->toArray()["nftables"] as $item)
    {
        $kinds[] = array_key_first($item);
    }

    // Chains come before the map whose elements jump to them, and everything comes before the rules.
    $expected = ["metainfo", "flush", "table", "chain", "chain", "chain", "map", "map", "counter", "flowtable"];
    SmokeTestRunner::assertSame([...$expected, "rule", "rule", "rule", "rule"], $kinds, "the items");
};

$description = "Ruleset: a rule brings the maps, flowtables and objects it uses";
$smoke->run($description, $testRuleAddsMapsFlowtablesAndObjects);

$testEmptyChainWithRules = function () : void {
    $table = Fixtures::createTable("t1");

    $createRuleset = function () use ($table) : void {
        $rules = new RuleCollection(Fixtures::createAcceptRule(Fixtures::createInputChain($table)));
        new Ruleset($rules, emptyChains: new EmptyChainCollection(Fixtures::createEmptyInputChain($table)));
    };

    $message = "The empty chain input in table ip t1 has the same name as a chain with rules.";
    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, $message);
};

$smoke->run("Ruleset: an empty chain with the same name as a chain with rules throws", $testEmptyChainWithRules);

$testSetsAndMapsShareNames = function () use ($matchSource) : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);

    $createRuleset = function () use ($table, $chain, $matchSource) : void {
        $set = NamedSet::create($table, "shared", SetType::IPV4_ADDR);
        $map = NamedMap::create($table, "shared", SetType::IPV4_ADDR, SetType::MARK);
        $sourceAddress = PayloadExpression::create(PayloadField::IP_SADDR);
        $setMark = new MangleStatement(new MetaExpression(MetaKey::MARK), $map->lookUp($sourceAddress));
        new Ruleset(new RuleCollection(Rule::create($chain, $matchSource($set)), Rule::create($chain, $setMark)));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "map shared");
};

$description = "Ruleset: a set and a map with the same name conflict, as nftables can't have both";
$smoke->run($description, $testSetsAndMapsShareNames);

$testDeduplication = function () use ($matchSource) : void {
    // Separate, but identical, instances each time, as a consumer building them in different places would have.
    $createSet = function () : NamedSet {
        return NamedSet::createAddressSet(Fixtures::createTable("t1"), "s", IpVersion::IPV4, "10.0.0.1");
    };

    $rules = new RuleCollection(
        Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "a"),
        Rule::create(Fixtures::createInputChain(Fixtures::createTable("t1")), $matchSource($createSet())),
        Rule::create(Fixtures::createInputChain(Fixtures::createTable("t1")), $matchSource($createSet())),
    );

    $ruleset = new Ruleset($rules);
    $expected = ["metainfo" => 1, "add" => 1, "delete" => 1, "table" => 1, "chain" => 1, "set" => 1, "rule" => 3];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$smoke->run("Ruleset: equal tables, sets and chains are only included once", $testDeduplication);

$testTablesInDifferentFamilies = function () use ($noRules) : void {
    $emptyTables = new EmptyTableCollection(new EmptyTable("f", Family::IP), new EmptyTable("f", Family::IP6));
    $ruleset = new Ruleset($noRules, emptyTables: $emptyTables);
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["table"], "the number of tables");
};

$smoke->run("Ruleset: same-named tables in different families are kept apart", $testTablesInDifferentFamilies);

$testEmptyTableInUse = function () : void {
    $rules = new RuleCollection(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1"))));

    $createRuleset = function () use ($rules) : void {
        new Ruleset($rules, emptyTables: new EmptyTableCollection(new EmptyTable("t1", Family::IP)));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "The empty table ip t1 is also in use");

    // The same name in another family is a different table.
    $ruleset = new Ruleset($rules, emptyTables: new EmptyTableCollection(new EmptyTable("t1", Family::IP6)));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["table"], "the number of tables");
};

$smoke->run("Ruleset: an empty table that's also in use throws", $testEmptyTableInUse);

$testDuplicateEmptyTables = function () use ($noRules) : void {
    $emptyTables = new EmptyTableCollection(new EmptyTable("t1", Family::IP), new EmptyTable("t1", Family::IP));
    $ruleset = new Ruleset($noRules, emptyTables: $emptyTables);
    SmokeTestRunner::assertSame(1, Fixtures::countItemTypes($ruleset)["table"], "the number of tables");
};

$smoke->run("Ruleset: the same empty table twice is only included once", $testDuplicateEmptyTables);

$testChainsInDifferentTables = function () use ($noRules) : void {
    $first = Fixtures::createEmptyInputChain(Fixtures::createTable("t1"));
    $second = Fixtures::createEmptyChain("input", Fixtures::createTable("t2"), Policy::ACCEPT);
    $ruleset = new Ruleset($noRules, emptyChains: new EmptyChainCollection($first, $second));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["chain"], "the number of chains");
};

$smoke->run("Ruleset: same-named chains in different tables are kept apart", $testChainsInDifferentTables);

$testSetAndChainShareName = function () use ($matchSource) : void {
    $table = Fixtures::createTable("t1");
    $input = Fixtures::createInputChain($table);
    $set = NamedSet::createAddressSet($table, "shared", IpVersion::IPV4);
    $jump = Rule::create($input, new JumpStatement(new RegularChain("shared", $table)));
    $ruleset = new Ruleset(new RuleCollection($jump, Rule::create($input, $matchSource($set), Verdict::DROP)));
    $counts = Fixtures::countItemTypes($ruleset);
    // The input chain, and the one called "shared".
    SmokeTestRunner::assertSame([2, 1], [$counts["chain"], $counts["set"]], "the number of chains and sets");
};

$smoke->run("Ruleset: a set and a chain can share a name", $testSetAndChainShareName);

$testChainConflict = function () use ($noRules) : void {
    $table = Fixtures::createTable("t1");

    $createRuleset = function () use ($noRules, $table) : void {
        $first = Fixtures::createEmptyChain("input", $table, Policy::DROP);
        $second = Fixtures::createEmptyChain("input", $table, Policy::ACCEPT);
        new Ruleset($noRules, emptyChains: new EmptyChainCollection($first, $second));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "chain input");
};

$smoke->run("Ruleset: two different chains with the same name throw", $testChainConflict);

$testSetConflict = function () use ($matchSource) : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);

    $createRuleset = function () use ($table, $chain, $matchSource) : void {
        $firstSet = NamedSet::createAddressSet($table, "s", IpVersion::IPV4, "10.0.0.1");
        $secondSet = NamedSet::createAddressSet($table, "s", IpVersion::IPV4, "10.0.0.2");
        $first = Rule::create($chain, $matchSource($firstSet));
        $second = Rule::create($chain, $matchSource($secondSet));
        new Ruleset(new RuleCollection($first, $second));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "set s");
};

$smoke->run("Ruleset: two different sets with the same name throw", $testSetConflict);

$testTableConflict = function () use ($noRules) : void {
    $createRuleset = function () use ($noRules) : void {
        $plain = Fixtures::createEmptyInputChain(new Table("t1", Family::IP));
        $dormantTable = new Table("t1", Family::IP, TableFlag::DORMANT);
        $dormant = Fixtures::createEmptyChain("other", $dormantTable, Policy::ACCEPT);
        new Ruleset($noRules, NftablesTarget::NFTABLES_1_1_3, emptyChains: new EmptyChainCollection($plain, $dormant));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "table t1");
};

$smoke->run("Ruleset: the same table with different flags throws", $testTableConflict);

$testRulesConflicting = function () : void {
    $table = Fixtures::createTable("t1");

    $createRuleset = function () use ($table) : void {
        $first = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, Policy::DROP));
        $second = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, Policy::ACCEPT));
        new Ruleset(new RuleCollection($first, $second));
    };

    SmokeTestRunner::expectException(ConflictException::class, $createRuleset, "chain input");
};

$smoke->run("Ruleset: rules whose chains conflict with each other throw", $testRulesConflicting);

$testCatchAll = function () use ($noRules) : void {
    $createRuleset = function () use ($noRules) : void {
        $plain = Fixtures::createEmptyInputChain(new Table("t1", Family::IP));
        $dormantTable = new Table("t1", Family::IP, TableFlag::DORMANT);
        $dormant = Fixtures::createEmptyChain("other", $dormantTable, Policy::ACCEPT);
        new Ruleset($noRules, NftablesTarget::NFTABLES_1_1_3, emptyChains: new EmptyChainCollection($plain, $dormant));
    };

    SmokeTestRunner::expectException(NftablesException::class, $createRuleset);
};

$smoke->run("Ruleset: every exception can be caught as an NftablesException", $testCatchAll);

$testJsonForms = function () : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);
    $rule = RuleFactory::createAcceptPort($chain, "eth0", 443, sourceAddress: "10.0.0.0/8", comment: "a/b");
    $ruleset = new Ruleset(new RuleCollection($rule));
    $decoded = json_decode($ruleset->toJson(), true, 512, JSON_THROW_ON_ERROR);
    // toArray() must be plain arrays all the way down, with no objects left for json_encode() to convert.
    SmokeTestRunner::assertSame($ruleset->toArray(), $decoded, "the decoded toJson()");
    SmokeTestRunner::assertSame(json_encode($ruleset->toArray()), json_encode($ruleset), "json_encode() output");
    SmokeTestRunner::assertTrue(str_contains($ruleset->toJson(), '"a/b"'), "slashes aren't escaped");
};

$smoke->run("Ruleset: toArray() is plain arrays, and the JSON forms match it", $testJsonForms);

$testInvalidUtf8 = function () : void {
    $chain = Fixtures::createInputChain(Fixtures::createTable("t1"));
    $ruleset = new Ruleset(new RuleCollection(Rule::create($chain, Verdict::ACCEPT)->withComment("\xB1\x31")));

    $encode = function () use ($ruleset) : void {
        $ruleset->toJson();
    };

    SmokeTestRunner::expectException(JsonException::class, $encode);
};

$smoke->run("Ruleset: invalid UTF-8 throws rather than giving an empty file", $testInvalidUtf8);

$testCollectionsCantBeChanged = function () : void {
    // The readonly classes hand out the collections they hold, so the collections mustn't be changeable either.
    $table = Fixtures::createTable("t1");
    $rule = Fixtures::createAcceptRule(Fixtures::createInputChain($table));

    $addAStatement = function () use ($rule) : void {
        $statements = $rule->getStatements();
        $statements[] = Verdict::DROP;
    };

    SmokeTestRunner::expectException(UnsupportedOperationException::class, $addAStatement);
    SmokeTestRunner::assertSame(1, count($rule->getStatements()), "the rule's statements");
    $chain = new RegularChain("target", $table);
    $jumpRule = Rule::create(Fixtures::createInputChain($table), new JumpStatement($chain));

    $removeAnItem = function () use ($jumpRule) : void {
        $items = $jumpRule->getReferencedItems();
        unset($items[0]);
    };

    SmokeTestRunner::expectException(UnsupportedOperationException::class, $removeAnItem);
    SmokeTestRunner::assertSame(1, count($jumpRule->getReferencedItems()), "the rule's referenced items");
};

$smoke->run("Ruleset: rules hand out collections that can't be changed", $testCollectionsCantBeChanged);

$testCollectionsRejectTheWrongType = function () : void {
    $createWithAString = function () : void {
        new SetFlagCollection("interval");
    };

    SmokeTestRunner::expectException(TypeError::class, $createWithAString);
};

$smoke->run("Ruleset: typed collections reject values of the wrong type", $testCollectionsRejectTheWrongType);
