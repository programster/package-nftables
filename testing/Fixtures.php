<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use Programster\Nftables\Chains\BaseChain;
use Programster\Nftables\Chains\EmptyChain;
use Programster\Nftables\Collections\EmptyChainCollection;
use Programster\Nftables\Collections\RuleCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Helpers\MatchFactory;
use Programster\Nftables\Rules\Rule;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Tables\Table;

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
     * @param Rule ...$extraRules - optionally, more rules to add after those two.
     *
     * @return Ruleset
     */
    public static function createTwoTableRuleset(RulesetResetMode $mode, Rule ...$extraRules) : Ruleset
    {
        $chain = self::createInputChain(self::createTable("ipv4Table"));
        $ipv6Table = new Table("ipv6Table", Family::IP6);
        $isLoopback = MatchFactory::createInputInterfaceName("lo");
        $loopbackRule = Rule::create($chain, $isLoopback, Verdict::ACCEPT)->withComment("lo");
        $rules = new RuleCollection($loopbackRule, self::createAcceptRule($chain, "second"), ...$extraRules);
        $emptyChains = new EmptyChainCollection(self::createEmptyInputChain($ipv6Table));
        return new Ruleset($rules, resetMode: $mode, emptyChains: $emptyChains);
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


    /**
     * Create an empty chain, the same as createChain() would, but with no rules allowed in it.
     *
     * @param string $name - the chain's name.
     *
     * @param Table $table - its table.
     *
     * @param Policy $policy - its policy.
     *
     * @return EmptyChain
     */
    public static function createEmptyChain(string $name, Table $table, Policy $policy) : EmptyChain
    {
        return new EmptyChain($name, $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, $policy);
    }


    public static function createEmptyInputChain(Table $table) : EmptyChain
    {
        return self::createEmptyChain("input", $table, Policy::DROP);
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
                $comments[] = JsonLib::getString($item, "rule", "comment");
            }
        }

        return $comments;
    }


    /**
     * Get the statements of a ruleset's only rule, as nftables' JSON.
     *
     * @param Rule $rule - the rule.
     *
     * @return list<array<string, mixed>>
     */
    public static function getRuleExpressions(Rule $rule) : array
    {
        return JsonLib::getObjectList($rule->toArray(), "rule", "expr");
    }
}
