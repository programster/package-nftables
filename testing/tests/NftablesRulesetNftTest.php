<?php

/*
 * Loads rulesets into real nft, to check it accepts them and they behave as intended when reloaded. Each test runs in
 * its own throwaway network namespace ("unshare -rn"), which needs no root and never touches the host's rules. They're
 * skipped (and reported as skipped) where nft or unprivileged user namespaces aren't available. These are run by
 * testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\Enums\NftablesRulesetResetMode;
use Programster\Nftables\NftablesRule;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\NftNamespace;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */
/** @var string $dir - a temporary directory for the tests to use, which is deleted afterwards. */

$registerNftTests = function (NftNamespace $nft) use ($smoke) : void {
    // What createTwoTableRuleset() should leave loaded.
    $expected = ["ip ipv4Table" => ["lo", "second"], "ip6 ipv6Table" => []];

    foreach (NftablesRulesetResetMode::cases() as $mode)
    {
        $testReload = function () use ($nft, $mode, $expected) : void {
            $file = $nft->writeRulesetFile("good-{$mode->name}.json", Fixtures::createTwoTableRuleset($mode));
            $listing = $nft->runInFreshNamespace([$nft->load($file), $nft->load($file)]);
            SmokeTestRunner::assertSame($expected, $listing, "what's loaded after loading twice");
        };

        $smoke->run("nft: loads on an empty ruleset, and reloading doesn't duplicate ({$mode->name})", $testReload);

        $testBadFile = function () use ($nft, $mode, $expected) : void {
            $good = $nft->writeRulesetFile("good-{$mode->name}.json", Fixtures::createTwoTableRuleset($mode));
            $ruleset = Fixtures::createTwoTableRuleset($mode);
            $chain = Fixtures::createInputChain(Fixtures::createTable("ipv4Table"));
            $ruleset->addRule(new NftablesRule($chain, [["nosuchexpression" => null]], "bad"));
            $bad = $nft->writeRulesetFile("bad-{$mode->name}.json", $ruleset);
            $listing = $nft->runInFreshNamespace([$nft->load($good), $nft->loadExpectingFailure($bad)]);
            SmokeTestRunner::assertSame($expected, $listing, "what's loaded after the bad file");
        };

        $smoke->run("nft: a file that fails to load changes nothing ({$mode->name})", $testBadFile);
    }

    $testKeepsForeignTables = function () use ($nft, $expected) : void {
        $ruleset = Fixtures::createTwoTableRuleset(NftablesRulesetResetMode::REPLACE_OWN_TABLES);
        $file = $nft->writeRulesetFile("replace.json", $ruleset);
        $listing = $nft->runInFreshNamespace([$nft->createForeignTable(), $nft->load($file)]);
        SmokeTestRunner::assertSame(["inet fail2ban" => []] + $expected, $listing, "what's loaded");
    };

    $smoke->run("nft: REPLACE_OWN_TABLES keeps tables created by other software", $testKeepsForeignTables);

    $testRemovesForeignTables = function () use ($nft, $expected) : void {
        $ruleset = Fixtures::createTwoTableRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
        $file = $nft->writeRulesetFile("flush.json", $ruleset);
        $listing = $nft->runInFreshNamespace([$nft->createForeignTable(), $nft->load($file)]);
        SmokeTestRunner::assertSame($expected, $listing, "what's loaded");
    };

    $smoke->run("nft: FLUSH_ENTIRE_RULESET removes tables created by other software", $testRemovesForeignTables);
};

try
{
    $registerNftTests(NftNamespace::create($dir));
}
catch (RuntimeException $e)
{
    // Only create() can throw here, as $smoke->run() catches anything a test throws.
    $smoke->skip("NftablesRuleset loaded into real nft", $e->getMessage());
}
