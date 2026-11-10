<?php

/*
 * Tests the JSON structure Ruleset produces, without needing nft. RulesetNftTest.php checks that real nft accepts it.
 * These are run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\BaseChain;
use Programster\Nftables\Collections\SetFlagCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\QuotaMatch;
use Programster\Nftables\Enums\QuotaUnit;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\TableFlag;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\ConflictException;
use Programster\Nftables\Exceptions\NftablesException;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Flowtable;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\NamedMap;
use Programster\Nftables\NamedSet;
use Programster\Nftables\NamedVerdictMap;
use Programster\Nftables\Objects\NamedCounter;
use Programster\Nftables\Objects\NamedQuota;
use Programster\Nftables\RegularChain;
use Programster\Nftables\Rule;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Statements\GotoStatement;
use Programster\Nftables\Statements\JumpStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\QuotaStatement;
use Programster\Nftables\Statements\SynproxyStatement;
use Programster\Nftables\Table;
use Programster\Nftables\VerdictMapElement;
use Ramsey\Collection\Exception\InvalidArgumentException;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */

$metainfo = ["metainfo" => ["json_schema_version" => 1]];

$testDefaultResetMode = function () : void {
    $ruleset = new Ruleset();
    $mode = $ruleset->getResetMode();
    SmokeTestRunner::assertSame(RulesetResetMode::REPLACE_OWN_TABLES, $mode, "the default reset mode");
};

$smoke->run("Ruleset: the default reset mode replaces its own tables", $testDefaultResetMode);

$testDefaultTarget = function () : void {
    $ruleset = new Ruleset();
    SmokeTestRunner::assertSame(NftablesTarget::NFTABLES_0_9_8, $ruleset->getTarget(), "the default target");
};

$smoke->run("Ruleset: the default target is the oldest supported nft", $testDefaultTarget);

$testRefusesForTarget = function () use ($metainfo) : void {
    $ruleset = new Ruleset(NftablesTarget::DEBIAN_12);

    $addDormantTable = function () use ($ruleset) : void {
        $ruleset->addTable(new Table("t1", Family::INET, TableFlag::DORMANT));
    };

    $message = "The dormant table flag needs nft 1.1.3 or later, but this ruleset is for Debian 12 (nft 1.0.6).";
    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $addDormantTable, $message);
    SmokeTestRunner::assertSame(["nftables" => [$metainfo]], $ruleset->toArray(), "the ruleset after");
};

$smoke->run("Ruleset: a feature its target can't load is refused, and not added", $testRefusesForTarget);

$testKernelRequirement = function () : void {
    $table = Fixtures::createTable("t");
    $synproxy = Rule::create(Fixtures::createInputChain($table), new SynproxyStatement(1460, 7));

    // Rocky 8's nft (1.0.4) handles a synproxy, but its kernel (4.18) doesn't have one, even with Red Hat's backports.
    $addToRocky8 = function () use ($synproxy) : void {
        (new Ruleset(NftablesTarget::ROCKY_8))->addRule($synproxy);
    };

    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $addToRocky8, "needs kernel 5.3");
    (new Ruleset(NftablesTarget::NFTABLES_1_0_4))->addRule($synproxy);
    (new Ruleset(NftablesTarget::ROCKY_9))->addRule($synproxy);
};

$smoke->run("Ruleset: an OS target also checks its kernel, and a version target doesn't", $testKernelRequirement);

$testRuleUsingUnsupportedChain = function () : void {
    $netdev = new Table("n", Family::NETDEV);
    $ingress = new BaseChain("i", $netdev, ChainType::FILTER, ChainHook::INGRESS, 0, Policy::ACCEPT, "lo");
    $ruleset = new Ruleset(NftablesTarget::UBUNTU_22_04);

    $addRule = function () use ($ruleset, $ingress) : void {
        $ruleset->addRule(Rule::create($ingress, Verdict::DROP));
    };

    SmokeTestRunner::expectException(UnsupportedFeatureException::class, $addRule, "ingress or egress hook");
    SmokeTestRunner::assertSame(0, count($ruleset->toArray()["nftables"]) - 1, "the number of items added");
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
        $ruleset = new Ruleset(resetMode: $mode);
        $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1"))));
        $first = $ruleset->toArray()["nftables"][0];
        SmokeTestRunner::assertSame($metainfo, $first, "the first item");
    };

    $smoke->run("Ruleset: the metainfo block comes first ({$mode->name})", $testMetainfoFirst);
}

$testReplaceOwnTables = function () use ($metainfo) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = new Table("t2", Family::IP6, TableFlag::DORMANT);
    $ruleset = new Ruleset(NftablesTarget::NFTABLES_1_1_3, RulesetResetMode::REPLACE_OWN_TABLES);
    $ruleset->addTable($table1);
    $ruleset->addTable($table2);

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

$testFlushEntireRuleset = function () use ($metainfo) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $ruleset = new Ruleset(resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addTable($table1);
    $ruleset->addTable($table2);
    $expected = [$metainfo, ["flush" => ["ruleset" => null]], $table1->toArray(), $table2->toArray()];
    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("Ruleset: FLUSH_ENTIRE_RULESET flushes once and deletes no tables", $testFlushEntireRuleset);

$testFlushIsJsonNull = function () : void {
    $ruleset = new Ruleset(resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $flush = json_decode($ruleset->toJson(), false, 512, JSON_THROW_ON_ERROR)->nftables[1]->flush;
    SmokeTestRunner::assertTrue(property_exists($flush, "ruleset"), "the flush has a ruleset key");
    SmokeTestRunner::assertSame(null, $flush->ruleset, "the flush's ruleset");
};

$smoke->run("Ruleset: the flush is encoded as JSON null", $testFlushIsJsonNull);

$testEmptyRuleset = function () use ($metainfo) : void {
    $ruleset = new Ruleset();
    SmokeTestRunner::assertSame(["nftables" => [$metainfo]], $ruleset->toArray(), "the empty ruleset");
};

$smoke->run("Ruleset: an empty ruleset is just the metainfo block", $testEmptyRuleset);

$testOrdering = function () use ($metainfo) : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $chain1 = Fixtures::createInputChain($table1);
    $chain2 = Fixtures::createInputChain($table2);
    $set = NamedSet::createAddressSet($table1, "blocklist", IpVersion::IPV4, "10.0.0.1");
    $rule = Fixtures::createAcceptRule($chain1);
    $ruleset = new Ruleset(resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addRule($rule);
    $ruleset->addChain($chain2);
    $ruleset->addSet($set);
    $ruleset->addTable($table2);

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
    $ruleset = new Ruleset(resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addRule($blockRule, Rule::create($chain, new JumpStatement($target)));
    $expected = ["metainfo" => 1, "flush" => 1, "table" => 1, "chain" => 2, "set" => 1, "rule" => 2];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$smoke->run("Ruleset: adding a rule adds its chain, table, jump targets and sets", $testRuleAddsWhatItUses);

$testRuleOrder = function () : void {
    $table = Fixtures::createTable("t1");
    $chain1 = Fixtures::createInputChain($table);
    $chain2 = Fixtures::createChain("other", $table, Policy::ACCEPT);
    $ruleset = new Ruleset();
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "first"), Fixtures::createAcceptRule($chain2, "second"));
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "third"));
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "fourth"));
    $comments = Fixtures::getRuleComments($ruleset);
    SmokeTestRunner::assertSame(["first", "second", "third", "fourth"], $comments, "the rules' order");
};

$smoke->run("Ruleset: rules keep the order they were added in", $testRuleOrder);

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
    // Flowtables need nft 1.0.6.
    $ruleset = new Ruleset(NftablesTarget::DEBIAN_12, RulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addRule(Rule::create($input, $services->lookUp($dport)), Rule::create($input, $setMark));
    $ruleset->addRule(Rule::create($input, $counter->createStatement()));
    $ruleset->addRule(RuleFactory::createFlowOffload($forward, $flowtable));
    $kinds = [];

    foreach ($ruleset->toArray()["nftables"] as $item)
    {
        $kinds[] = array_key_first($item);
    }

    // Chains come before the map whose elements jump to them, and everything comes before the rules.
    $expected = ["metainfo", "flush", "table", "chain", "chain", "chain", "map", "map", "counter", "flowtable"];
    SmokeTestRunner::assertSame([...$expected, "rule", "rule", "rule", "rule"], $kinds, "the items");
};

$description = "Ruleset: adding a rule adds the maps, flowtables and objects it uses";
$smoke->run($description, $testRuleAddsMapsFlowtablesAndObjects);

$testAddingItemsDirectly = function () : void {
    $table = Fixtures::createTable("t1");
    $web = new RegularChain("web", $table);
    $services = NamedVerdictMap::create($table, "services", SetType::INET_SERVICE);
    $ruleset = new Ruleset(NftablesTarget::DEBIAN_12);
    $ruleset->addMap($services->withElements(new VerdictMapElement(80, new GotoStatement($web))));
    $ruleset->addFlowtable(new Flowtable("fastpath", $table, 0, "eth0"));
    $ruleset->addObject(new NamedCounter("web", $table));
    // A counter and a quota can share a name, as each kind of object has names of its own.
    $quota = new QuotaStatement(1, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA);
    $ruleset->addObject(new NamedQuota("web", $table, $quota));
    $expected = ["metainfo" => 1, "add" => 1, "delete" => 1, "table" => 1, "chain" => 1, "map" => 1];
    $expected = [...$expected, "flowtable" => 1, "counter" => 1, "quota" => 1];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$description = "Ruleset: maps, flowtables and objects can be added directly, with what they use";
$smoke->run($description, $testAddingItemsDirectly);

$testSetsAndMapsShareNames = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $ruleset->addSet(NamedSet::create($table, "shared", SetType::IPV4_ADDR));

    $addMap = function () use ($ruleset, $table) : void {
        $ruleset->addMap(NamedMap::create($table, "shared", SetType::IPV4_ADDR, SetType::MARK));
    };

    SmokeTestRunner::expectException(ConflictException::class, $addMap, "map shared");
};

$description = "Ruleset: a set and a map with the same name conflict, as nftables can't have both";
$smoke->run($description, $testSetsAndMapsShareNames);

$testDeduplication = function () : void {
    $ruleset = new Ruleset();
    // Separate, but identical, instances each time, as a consumer building them in different places would have.
    $ruleset->addTable(Fixtures::createTable("t1"));
    $ruleset->addTable(Fixtures::createTable("t1"));
    $ruleset->addChain(Fixtures::createInputChain(Fixtures::createTable("t1")));
    $ruleset->addSet(NamedSet::createAddressSet(Fixtures::createTable("t1"), "s", IpVersion::IPV4, "10.0.0.1"));
    $ruleset->addSet(NamedSet::createAddressSet(Fixtures::createTable("t1"), "s", IpVersion::IPV4, "10.0.0.1"));
    $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "a"));
    $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "b"));
    $expected = ["metainfo" => 1, "add" => 1, "delete" => 1, "table" => 1, "chain" => 1, "set" => 1, "rule" => 2];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$smoke->run("Ruleset: equal tables, sets and chains are only included once", $testDeduplication);

$testTablesInDifferentFamilies = function () : void {
    $ruleset = new Ruleset();
    $ruleset->addTable(new Table("filter", Family::IP));
    $ruleset->addTable(new Table("filter", Family::IP6));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["table"], "the number of tables");
};

$smoke->run("Ruleset: same-named tables in different families are kept apart", $testTablesInDifferentFamilies);

$testChainsInDifferentTables = function () : void {
    $ruleset = new Ruleset();
    $ruleset->addChain(Fixtures::createInputChain(Fixtures::createTable("t1")));
    $ruleset->addChain(Fixtures::createChain("input", Fixtures::createTable("t2"), Policy::ACCEPT));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["chain"], "the number of chains");
};

$smoke->run("Ruleset: same-named chains in different tables are kept apart", $testChainsInDifferentTables);

$testSetAndChainShareName = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $ruleset->addChain(new RegularChain("shared", $table));
    $ruleset->addSet(NamedSet::createAddressSet($table, "shared", IpVersion::IPV4));
    $counts = Fixtures::countItemTypes($ruleset);
    SmokeTestRunner::assertSame([1, 1], [$counts["chain"], $counts["set"]], "the number of chains and sets");
};

$smoke->run("Ruleset: a set and a chain can share a name", $testSetAndChainShareName);

$testChainConflict = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $ruleset->addChain(Fixtures::createChain("input", $table, Policy::DROP));

    $addConflictingChain = function () use ($ruleset, $table) : void {
        $ruleset->addChain(Fixtures::createChain("input", $table, Policy::ACCEPT));
    };

    SmokeTestRunner::expectException(ConflictException::class, $addConflictingChain, "chain input");
};

$smoke->run("Ruleset: adding a different chain with the same name throws", $testChainConflict);

$testSetConflict = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $ruleset->addSet(NamedSet::createAddressSet($table, "s", IpVersion::IPV4, "10.0.0.1"));

    $addConflictingSet = function () use ($ruleset, $table) : void {
        $ruleset->addSet(NamedSet::createAddressSet($table, "s", IpVersion::IPV4, "10.0.0.2"));
    };

    SmokeTestRunner::expectException(ConflictException::class, $addConflictingSet, "set s");
};

$smoke->run("Ruleset: adding a different set with the same name throws", $testSetConflict);

$testTableConflict = function () : void {
    $ruleset = new Ruleset(NftablesTarget::NFTABLES_1_1_3);
    $ruleset->addTable(new Table("t1", Family::IP));

    $addConflictingTable = function () use ($ruleset) : void {
        $ruleset->addChain(Fixtures::createInputChain(new Table("t1", Family::IP, TableFlag::DORMANT)));
    };

    SmokeTestRunner::expectException(ConflictException::class, $addConflictingTable, "table t1");
};

$smoke->run("Ruleset: adding the same table with different flags throws", $testTableConflict);

$testConflictAddsNoRules = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $ruleset->addChain(Fixtures::createChain("input", $table, Policy::DROP));
    $before = $ruleset->toArray();

    $addRules = function () use ($ruleset, $table) : void {
        $fine = Fixtures::createAcceptRule(Fixtures::createChain("other", $table, Policy::ACCEPT));
        $conflicting = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, Policy::ACCEPT));
        $ruleset->addRule($fine, $conflicting);
    };

    SmokeTestRunner::expectException(ConflictException::class, $addRules);
    SmokeTestRunner::assertSame($before, $ruleset->toArray(), "the ruleset after the conflict");
};

$smoke->run("Ruleset: adding rules where one chain conflicts adds none of them", $testConflictAddsNoRules);

$testRulesConflicting = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new Ruleset();
    $before = $ruleset->toArray();

    $addRules = function () use ($ruleset, $table) : void {
        $first = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, Policy::DROP));
        $second = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, Policy::ACCEPT));
        $ruleset->addRule($first, $second);
    };

    SmokeTestRunner::expectException(ConflictException::class, $addRules);
    SmokeTestRunner::assertSame($before, $ruleset->toArray(), "the ruleset after the conflict");
};

$smoke->run("Ruleset: rules whose chains conflict with each other aren't added", $testRulesConflicting);

$testCatchAll = function () : void {
    $ruleset = new Ruleset(NftablesTarget::NFTABLES_1_1_3);
    $ruleset->addTable(new Table("t1", Family::IP));

    $addConflictingTable = function () use ($ruleset) : void {
        $ruleset->addTable(new Table("t1", Family::IP, TableFlag::DORMANT));
    };

    SmokeTestRunner::expectException(NftablesException::class, $addConflictingTable);
};

$smoke->run("Ruleset: every exception can be caught as an NftablesException", $testCatchAll);

$testJsonForms = function () : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);
    $ruleset = new Ruleset();
    $ruleset->addRule(RuleFactory::createAcceptPort($chain, "eth0", 443, sourceAddress: "10.0.0.0/8", comment: "a/b"));
    $decoded = json_decode($ruleset->toJson(), true, 512, JSON_THROW_ON_ERROR);
    // toArray() must be plain arrays all the way down, with no objects left for json_encode() to convert.
    SmokeTestRunner::assertSame($ruleset->toArray(), $decoded, "the decoded toJson()");
    SmokeTestRunner::assertSame(json_encode($ruleset->toArray()), json_encode($ruleset), "json_encode() output");
    SmokeTestRunner::assertTrue(str_contains($ruleset->toJson(), '"a/b"'), "slashes aren't escaped");
};

$smoke->run("Ruleset: toArray() is plain arrays, and the JSON forms match it", $testJsonForms);

$testInvalidUtf8 = function () : void {
    $ruleset = new Ruleset();
    $chain = Fixtures::createInputChain(Fixtures::createTable("t1"));
    $ruleset->addRule(Rule::create($chain, Verdict::ACCEPT)->withComment("\xB1\x31"));

    $encode = function () use ($ruleset) : void {
        $ruleset->toJson();
    };

    SmokeTestRunner::expectException(JsonException::class, $encode);
};

$smoke->run("Ruleset: invalid UTF-8 throws rather than giving an empty file", $testInvalidUtf8);

$testCollectionsAreCopied = function () : void {
    // Collections can be changed, so the readonly classes that hold them must only ever hand out copies.
    $table = Fixtures::createTable("t1");
    $rule = Fixtures::createAcceptRule(Fixtures::createInputChain($table));
    $statements = $rule->getStatements();
    $statements->add(Verdict::DROP);
    SmokeTestRunner::assertSame(1, count($rule->getStatements()), "the rule's statements");
    $chain = new RegularChain("target", $table);
    $jumpRule = Rule::create(Fixtures::createInputChain($table), new JumpStatement($chain));
    $items = $jumpRule->getReferencedItems();
    $items->clear();
    SmokeTestRunner::assertSame(1, count($jumpRule->getReferencedItems()), "the rule's referenced items");
};

$smoke->run("Ruleset: rules hand out copies of their collections, so they can't be changed", $testCollectionsAreCopied);

$testCollectionsRejectTheWrongType = function () : void {
    $addAString = function () : void {
        $flags = new SetFlagCollection();
        $flags->add("interval");
    };

    SmokeTestRunner::expectException(InvalidArgumentException::class, $addAString);
};

$smoke->run("Ruleset: typed collections reject values of the wrong type", $testCollectionsRejectTheWrongType);
