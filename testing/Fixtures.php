<?php

namespace Programster\Nftables\Testing;

use Programster\Nftables\Enums\NftablesChainHook;
use Programster\Nftables\Enums\NftablesChainType;
use Programster\Nftables\Enums\NftablesFamily;
use Programster\Nftables\Enums\NftablesPolicy;
use Programster\Nftables\Enums\NftablesPriority;
use Programster\Nftables\Enums\NftablesRulesetResetMode;
use Programster\Nftables\NftablesChain;
use Programster\Nftables\NftablesRule;
use Programster\Nftables\NftablesRuleset;
use Programster\Nftables\NftablesTable;

/**
 * Builds the tables, chains, rules and rulesets the tests use.
 */
final class Fixtures
{
    /**
     * Create a ruleset with an IPv4 table holding two rules (commented "lo" and "second"), and an IPv6 table holding
     * just a chain.
     *
     * @param NftablesRulesetResetMode $mode - the reset mode to give it.
     *
     * @return NftablesRuleset
     */
    public static function createTwoTableRuleset(NftablesRulesetResetMode $mode) : NftablesRuleset
    {
        $chain = self::createInputChain(self::createTable("ipv4Table"));
        $isLoopback = ["match" => ["op" => "==", "left" => ["meta" => ["key" => "iifname"]], "right" => "lo"]];
        $ipv6Table = new NftablesTable("ipv6Table", NftablesFamily::IP6);
        $ruleset = new NftablesRuleset($mode);
        $ruleset->addChain(self::createInputChain($ipv6Table));
        $ruleset->addRule(new NftablesRule($chain, [$isLoopback, ["accept" => null]], "lo"));
        $ruleset->addRule(self::createAcceptRule($chain, "second"));
        return $ruleset;
    }


    public static function createTable(string $name) : NftablesTable
    {
        return new NftablesTable($name, NftablesFamily::IP);
    }


    public static function createInputChain(NftablesTable $table) : NftablesChain
    {
        return self::createChain("input", $table, NftablesPolicy::DROP);
    }


    public static function createChain(string $name, NftablesTable $table, NftablesPolicy $policy) : NftablesChain
    {
        return new NftablesChain(
            $name,
            $table,
            NftablesChainType::FILTER,
            NftablesChainHook::INPUT,
            NftablesPriority::NF_IP_PRI_FILTER,
            $policy,
        );
    }


    public static function createAcceptRule(NftablesChain $chain, string $comment = "accept") : NftablesRule
    {
        return new NftablesRule($chain, [["accept" => null]], $comment);
    }


    /**
     * Count how many of each kind of item (keyed by its top-level key, e.g. "table" or "rule") a ruleset has.
     *
     * @param NftablesRuleset $ruleset - the ruleset.
     *
     * @return array<string, int>
     */
    public static function countItemTypes(NftablesRuleset $ruleset) : array
    {
        $counts = [];

        foreach ($ruleset->toArray()["nftables"] as $item)
        {
            $type = array_key_first($item);
            $counts[$type] = ($counts[$type] ?? 0) + 1;
        }

        return $counts;
    }


    /**
     * Get the comments of a ruleset's rules, in order.
     *
     * @param NftablesRuleset $ruleset - the ruleset.
     *
     * @return string[]
     */
    public static function getRuleComments(NftablesRuleset $ruleset) : array
    {
        $comments = [];

        foreach ($ruleset->toArray()["nftables"] as $item)
        {
            if (isset($item["rule"]))
            {
                $comments[] = $item["rule"]["comment"];
            }
        }

        return $comments;
    }
}
