<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use Programster\Nftables\BaseChain;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\Rule;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

/**
 * Builds the tables, chains, rules and rulesets the tests use.
 */
final class Fixtures
{
    private function __construct()
    {
    }


    /**
     * Create a ruleset with an IPv4 table holding two rules (commented "lo" and "second"), and an IPv6 table holding
     * just a chain.
     *
     * @param RulesetResetMode $mode - the reset mode to give it.
     *
     * @return Ruleset
     */
    public static function createTwoTableRuleset(RulesetResetMode $mode) : Ruleset
    {
        $chain = self::createInputChain(self::createTable("ipv4Table"));
        $ipv6Table = new Table("ipv6Table", Family::IP6);
        $ruleset = new Ruleset(resetMode: $mode);
        $ruleset->addChain(self::createInputChain($ipv6Table));
        $isLoopback = MatchFactory::createInputInterfaceName("lo");
        $ruleset->addRule(Rule::create($chain, $isLoopback, Verdict::ACCEPT)->withComment("lo"));
        $ruleset->addRule(self::createAcceptRule($chain, "second"));
        return $ruleset;
    }


    public static function createTable(string $name, Family $family = Family::IP) : Table
    {
        return new Table($name, $family);
    }


    public static function createInputChain(Table $table) : BaseChain
    {
        return self::createChain("input", $table, Policy::DROP);
    }


    public static function createChain(string $name, Table $table, Policy $policy) : BaseChain
    {
        return new BaseChain($name, $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, $policy);
    }


    public static function createBaseChain(Table $table, ChainType $type, ChainHook $hook) : BaseChain
    {
        $priority = match ($type) {
            ChainType::NAT => ($hook === ChainHook::POSTROUTING) ? Priority::SRCNAT : Priority::DSTNAT,
            default => Priority::FILTER,
        };

        return new BaseChain($hook->value, $table, $type, $hook, $priority, Policy::ACCEPT);
    }


    public static function createAcceptRule(BaseChain $chain, string $comment = "accept") : Rule
    {
        return Rule::create($chain, Verdict::ACCEPT)->withComment($comment);
    }


    /**
     * Count how many of each kind of item (keyed by its top-level key, e.g. "table" or "rule") a ruleset has.
     *
     * @param Ruleset $ruleset - the ruleset.
     *
     * @return array<string, int>
     */
    public static function countItemTypes(Ruleset $ruleset) : array
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
     * @param Ruleset $ruleset - the ruleset.
     *
     * @return string[]
     */
    public static function getRuleComments(Ruleset $ruleset) : array
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


    /**
     * Get the statements of a ruleset's only rule, as nftables' JSON.
     *
     * @param Rule $rule - the rule.
     *
     * @return array
     */
    public static function getRuleExpressions(Rule $rule) : array
    {
        return $rule->toArray()["rule"]["expr"];
    }
}
