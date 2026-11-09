<?php

/*
 * Tests the JSON structure NftablesRuleset produces, without needing nft. NftablesRulesetNftTest.php checks that real
 * nft accepts it. These are run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\Enums\NftablesFamily;
use Programster\Nftables\Enums\NftablesPolicy;
use Programster\Nftables\Enums\NftablesRulesetResetMode;
use Programster\Nftables\Exceptions\ExceptionChainConflict;
use Programster\Nftables\NftablesLib;
use Programster\Nftables\NftablesRule;
use Programster\Nftables\NftablesRuleset;
use Programster\Nftables\NftablesTable;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */

$testDefaultResetMode = function () : void {
    $ruleset = new NftablesRuleset();
    $mode = $ruleset->getResetMode();
    SmokeTestRunner::assertSame(NftablesRulesetResetMode::REPLACE_OWN_TABLES, $mode, "the default reset mode");
};

$smoke->run("NftablesRuleset: the default reset mode replaces its own tables", $testDefaultResetMode);

foreach (NftablesRulesetResetMode::cases() as $mode)
{
    $testMetainfoFirst = function () use ($mode) : void {
        $ruleset = new NftablesRuleset($mode);
        $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1"))));
        $first = $ruleset->toArray()["nftables"][0];
        SmokeTestRunner::assertSame(NftablesLib::createMetaInfoBlock(), $first, "the first item");
    };

    $smoke->run("NftablesRuleset: the metainfo block comes first ({$mode->name})", $testMetainfoFirst);
}

$testReplaceOwnTables = function () : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = new NftablesTable("t2", NftablesFamily::IP6);
    $ruleset = new NftablesRuleset(NftablesRulesetResetMode::REPLACE_OWN_TABLES);
    $ruleset->addTable($table1);
    $ruleset->addTable($table2);

    $expected = [
        NftablesLib::createMetaInfoBlock(),
        ["add" => $table1->toArray()],
        ["delete" => $table1->toArray()],
        ["add" => $table2->toArray()],
        ["delete" => $table2->toArray()],
        $table1->toArray(),
        $table2->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
    SmokeTestRunner::assertTrue(!str_contains($ruleset->toJson(), '"flush"'), "the JSON has no flush");
};

$smoke->run("NftablesRuleset: REPLACE_OWN_TABLES adds then deletes each table first", $testReplaceOwnTables);

$testFlushEntireRuleset = function () : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $ruleset = new NftablesRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addTable($table1);
    $ruleset->addTable($table2);

    $expected = [
        NftablesLib::createMetaInfoBlock(),
        ["flush" => ["ruleset" => null]],
        $table1->toArray(),
        $table2->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("NftablesRuleset: FLUSH_ENTIRE_RULESET flushes once and deletes no tables", $testFlushEntireRuleset);

$testFlushIsJsonNull = function () : void {
    $ruleset = new NftablesRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
    $flush = json_decode($ruleset->toJson(), false, 512, JSON_THROW_ON_ERROR)->nftables[1]->flush;
    SmokeTestRunner::assertTrue(property_exists($flush, "ruleset"), "the flush has a ruleset key");
    SmokeTestRunner::assertSame(null, $flush->ruleset, "the flush's ruleset");
};

$smoke->run("NftablesRuleset: the flush is encoded as JSON null", $testFlushIsJsonNull);

$testEmptyRuleset = function () : void {
    $ruleset = new NftablesRuleset();
    $expected = ["nftables" => [NftablesLib::createMetaInfoBlock()]];
    SmokeTestRunner::assertSame($expected, $ruleset->toArray(), "the empty ruleset");
};

$smoke->run("NftablesRuleset: an empty ruleset is just the metainfo block", $testEmptyRuleset);

$testOrdering = function () : void {
    $table1 = Fixtures::createTable("t1");
    $table2 = Fixtures::createTable("t2");
    $chain1 = Fixtures::createInputChain($table1);
    $chain2 = Fixtures::createInputChain($table2);
    $rule = Fixtures::createAcceptRule($chain1);
    $ruleset = new NftablesRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addRule($rule);
    $ruleset->addChain($chain2);
    $ruleset->addTable($table2);

    $expected = [
        NftablesLib::createMetaInfoBlock(),
        ["flush" => ["ruleset" => null]],
        $table1->toArray(),
        $table2->toArray(),
        $chain1->toArray(),
        $chain2->toArray(),
        $rule->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("NftablesRuleset: tables come before chains, and chains before rules", $testOrdering);

$testRuleAddsChainAndTable = function () : void {
    $table = Fixtures::createTable("t1");
    $chain = Fixtures::createInputChain($table);
    $rule = Fixtures::createAcceptRule($chain);
    $ruleset = new NftablesRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
    $ruleset->addRule($rule);

    $expected = [
        NftablesLib::createMetaInfoBlock(),
        ["flush" => ["ruleset" => null]],
        $table->toArray(),
        $chain->toArray(),
        $rule->toArray(),
    ];

    SmokeTestRunner::assertSame(["nftables" => $expected], $ruleset->toArray(), "the ruleset");
};

$smoke->run("NftablesRuleset: adding a rule adds its chain and table", $testRuleAddsChainAndTable);

$testRuleOrder = function () : void {
    $table = Fixtures::createTable("t1");
    $chain1 = Fixtures::createInputChain($table);
    $chain2 = Fixtures::createChain("other", $table, NftablesPolicy::ACCEPT);
    $ruleset = new NftablesRuleset();
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "first"), Fixtures::createAcceptRule($chain2, "second"));
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "third"));
    $ruleset->addRule(Fixtures::createAcceptRule($chain1, "fourth"));
    $comments = Fixtures::getRuleComments($ruleset);
    SmokeTestRunner::assertSame(["first", "second", "third", "fourth"], $comments, "the rules' order");
};

$smoke->run("NftablesRuleset: rules keep the order they were added in", $testRuleOrder);

$testDeduplication = function () : void {
    $ruleset = new NftablesRuleset();
    // Separate, but identical, instances each time, as a consumer building them in different places would have.
    $ruleset->addTable(Fixtures::createTable("t1"));
    $ruleset->addTable(Fixtures::createTable("t1"));
    $ruleset->addChain(Fixtures::createInputChain(Fixtures::createTable("t1")));
    $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "a"));
    $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "b"));
    $expected = ["metainfo" => 1, "add" => 1, "delete" => 1, "table" => 1, "chain" => 1, "rule" => 2];
    SmokeTestRunner::assertSame($expected, Fixtures::countItemTypes($ruleset), "the number of each item");
};

$smoke->run("NftablesRuleset: equal tables and chains are only included once", $testDeduplication);

$testTablesInDifferentFamilies = function () : void {
    $ruleset = new NftablesRuleset();
    $ruleset->addTable(new NftablesTable("filter", NftablesFamily::IP));
    $ruleset->addTable(new NftablesTable("filter", NftablesFamily::IP6));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["table"], "the number of tables");
};

$smoke->run("NftablesRuleset: same-named tables in different families are kept apart", $testTablesInDifferentFamilies);

$testChainsInDifferentTables = function () : void {
    $ruleset = new NftablesRuleset();
    $ruleset->addChain(Fixtures::createInputChain(Fixtures::createTable("t1")));
    $ruleset->addChain(Fixtures::createChain("input", Fixtures::createTable("t2"), NftablesPolicy::ACCEPT));
    SmokeTestRunner::assertSame(2, Fixtures::countItemTypes($ruleset)["chain"], "the number of chains");
};

$smoke->run("NftablesRuleset: same-named chains in different tables are kept apart", $testChainsInDifferentTables);

$testChainConflict = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new NftablesRuleset();
    $ruleset->addChain(Fixtures::createChain("input", $table, NftablesPolicy::DROP));

    $addConflictingChain = function () use ($ruleset, $table) : void {
        $ruleset->addChain(Fixtures::createChain("input", $table, NftablesPolicy::ACCEPT));
    };

    SmokeTestRunner::expectException(ExceptionChainConflict::class, $addConflictingChain);
};

$smoke->run("NftablesRuleset: adding a different chain with the same name throws", $testChainConflict);

$testConflictAddsNoRules = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new NftablesRuleset();
    $ruleset->addChain(Fixtures::createChain("input", $table, NftablesPolicy::DROP));
    $before = $ruleset->toArray();

    $addRules = function () use ($ruleset, $table) : void {
        $fine = Fixtures::createAcceptRule(Fixtures::createChain("other", $table, NftablesPolicy::ACCEPT));
        $conflicting = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, NftablesPolicy::ACCEPT));
        $ruleset->addRule($fine, $conflicting);
    };

    SmokeTestRunner::expectException(ExceptionChainConflict::class, $addRules);
    SmokeTestRunner::assertSame($before, $ruleset->toArray(), "the ruleset after the conflict");
};

$smoke->run("NftablesRuleset: adding rules where one chain conflicts adds none of them", $testConflictAddsNoRules);

$testRulesConflicting = function () : void {
    $table = Fixtures::createTable("t1");
    $ruleset = new NftablesRuleset();
    $before = $ruleset->toArray();

    $addRules = function () use ($ruleset, $table) : void {
        $first = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, NftablesPolicy::DROP));
        $second = Fixtures::createAcceptRule(Fixtures::createChain("input", $table, NftablesPolicy::ACCEPT));
        $ruleset->addRule($first, $second);
    };

    SmokeTestRunner::expectException(ExceptionChainConflict::class, $addRules);
    SmokeTestRunner::assertSame($before, $ruleset->toArray(), "the ruleset after the conflict");
};

$smoke->run("NftablesRuleset: rules whose chains conflict with each other aren't added", $testRulesConflicting);

$testJsonForms = function () : void {
    $ruleset = new NftablesRuleset();
    $ruleset->addRule(Fixtures::createAcceptRule(Fixtures::createInputChain(Fixtures::createTable("t1")), "a/b"));
    $decoded = json_decode($ruleset->toJson(), true, 512, JSON_THROW_ON_ERROR);
    SmokeTestRunner::assertSame($ruleset->toArray(), $decoded, "the decoded toJson()");
    SmokeTestRunner::assertSame(json_encode($ruleset->toArray()), json_encode($ruleset), "json_encode() output");
    SmokeTestRunner::assertTrue(str_contains($ruleset->toJson(), '"a/b"'), "slashes aren't escaped");
};

$smoke->run("NftablesRuleset: the JSON forms all match the array form", $testJsonForms);

$testInvalidUtf8 = function () : void {
    $ruleset = new NftablesRuleset();
    $chain = Fixtures::createInputChain(Fixtures::createTable("t1"));
    $ruleset->addRule(new NftablesRule($chain, [["accept" => null]], "\xB1\x31"));

    $encode = function () use ($ruleset) : void {
        $ruleset->toJson();
    };

    SmokeTestRunner::expectException(JsonException::class, $encode);
};

$smoke->run("NftablesRuleset: invalid UTF-8 throws rather than giving an empty file", $testInvalidUtf8);
