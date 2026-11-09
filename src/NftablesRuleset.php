<?php

namespace Programster\Nftables;

use JsonException;
use JsonSerializable;
use Programster\Nftables\Enums\NftablesRulesetResetMode;
use Programster\Nftables\Exceptions\ExceptionChainConflict;

/**
 * A complete nftables ruleset, ready to be loaded with "nft --json --file". It takes care of the things that are easy
 * to get wrong when putting the JSON together by hand:
 *
 * - the metainfo block always comes first.
 *
 * - it clears out the old version of the rules first, in the same transaction as the load, so reloading never stacks
 * up duplicate rules, and a ruleset that fails to load leaves the previous rules in place.
 *
 * - tables come before chains, and chains before rules, so nothing refers to something that doesn't exist yet.
 *
 * Adding a chain or rule automatically adds the table (and chain) it belongs to, so only chains with no rules (e.g. a
 * chain that exists just for its drop policy) need adding explicitly.
 *
 * This is mutable by design, as it's built up one item at a time.
 */
class NftablesRuleset implements JsonSerializable
{
    private readonly NftablesRulesetResetMode $m_resetMode;

    /** @var array<string, NftablesTable> - keyed by family and name. */
    private array $m_tables;

    /** @var array<string, NftablesChain> - keyed by family, table name and chain name. */
    private array $m_chains;

    /** @var NftablesRule[] - in the order they were added, which is the order nftables evaluates them in. */
    private array $m_rules;


    /**
     * Create an empty ruleset.
     *
     * @param NftablesRulesetResetMode $resetMode - what to clear out before loading this ruleset. Defaults to only
     * replacing the tables this ruleset defines, leaving any tables created by other software (e.g. fail2ban or
     * Docker) alone. Pass FLUSH_ENTIRE_RULESET to wipe everything on the machine first.
     */
    public function __construct(
        NftablesRulesetResetMode $resetMode = NftablesRulesetResetMode::REPLACE_OWN_TABLES,
    )
    {
        $this->m_resetMode = $resetMode;
        $this->m_tables = [];
        $this->m_chains = [];
        $this->m_rules = [];
    }


    /**
     * Add a table. Adding the same table (same family and name) again has no effect.
     *
     * @param NftablesTable $table - the table to add.
     *
     * @return void
     */
    public function addTable(NftablesTable $table) : void
    {
        $this->m_tables[self::getTableKey($table)] = $table;
    }


    /**
     * Add a chain, and the table it belongs to. Adding the same chain again has no effect.
     *
     * @param NftablesChain $chain - the chain to add.
     *
     * @return void
     *
     * @throws ExceptionChainConflict - if a different chain with the same name, in the same table, was already added.
     */
    public function addChain(NftablesChain $chain) : void
    {
        self::assertNoChainConflict($this->m_chains, $chain);
        $this->addTable($chain->getTable());
        $this->m_chains[self::getChainKey($chain)] = $chain;
    }


    /**
     * Add one or more rules to the end of the ruleset, along with the chains and tables they belong to. Rules are
     * evaluated in the order they're added, so add them in the order you want them to be matched.
     *
     * @param NftablesRule ...$rules - the rule(s) to add.
     *
     * @return void
     *
     * @throws ExceptionChainConflict - if a rule's chain has the same name as a different chain in the same table,
     * either one already added or another rule's. None of the rules are added if this is thrown.
     */
    public function addRule(NftablesRule ...$rules) : void
    {
        // Check them all first (against each other too), so a conflict part way through doesn't leave only some of
        // the rules added.
        $chains = $this->m_chains;

        foreach ($rules as $rule)
        {
            self::assertNoChainConflict($chains, $rule->getChain());
            $chains[self::getChainKey($rule->getChain())] = $rule->getChain();
        }

        foreach ($rules as $rule)
        {
            $this->addChain($rule->getChain());
            $this->m_rules[] = $rule;
        }
    }


    /**
     * Get the ruleset in the array form that nftables expects, ready to be JSON encoded.
     *
     * @return array
     */
    public function toArray() : array
    {
        $items = [NftablesLib::createMetaInfoBlock()];

        if ($this->m_resetMode === NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET)
        {
            $items[] = ["flush" => ["ruleset" => null]];
        }
        else
        {
            // Adding the table first means the delete can't fail if the table doesn't exist yet (e.g. on first boot).
            foreach ($this->m_tables as $table)
            {
                $items[] = ["add" => $table->toArray()];
                $items[] = ["delete" => $table->toArray()];
            }
        }

        foreach ($this->m_tables as $table)
        {
            $items[] = $table->toArray();
        }

        foreach ($this->m_chains as $chain)
        {
            $items[] = $chain->toArray();
        }

        foreach ($this->m_rules as $rule)
        {
            $items[] = $rule->toArray();
        }

        return ["nftables" => $items];
    }


    /**
     * Get the ruleset in the form json_encode() should use, so it can be encoded directly.
     *
     * @return array
     */
    public function jsonSerialize() : array
    {
        return $this->toArray();
    }


    /**
     * Get the ruleset as pretty printed JSON, ready to be written to a file and loaded with "nft --json --file".
     *
     * @return string
     *
     * @throws JsonException - if the ruleset can't be encoded, e.g. a comment isn't valid UTF-8.
     */
    public function toJson() : string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }


    /**
     * Check that none of the chains already added is a different chain with the same family, table and name.
     *
     * @param array<string, NftablesChain> $existingChains - the chains already added, keyed by getChainKey().
     *
     * @param NftablesChain $chain - the chain about to be added.
     *
     * @return void
     *
     * @throws ExceptionChainConflict - if a different chain with the same name was already added to its table.
     */
    private static function assertNoChainConflict(array $existingChains, NftablesChain $chain) : void
    {
        $key = self::getChainKey($chain);

        if (isset($existingChains[$key]) && $existingChains[$key]->toArray() !== $chain->toArray())
        {
            $tableName = $chain->getTable()->getName();

            throw new ExceptionChainConflict(
                "A different chain called {$chain->getName()} has already been added to table {$tableName}."
            );
        }
    }


    /**
     * Get the key a table is stored under, which is unique to its family and name.
     *
     * @param NftablesTable $table - the table to get the key for.
     *
     * @return string
     */
    private static function getTableKey(NftablesTable $table) : string
    {
        return $table->getFamily()->value . ' ' . $table->getName();
    }


    /**
     * Get the key a chain is stored under, which is unique to its table's family and name, and its own name.
     *
     * @param NftablesChain $chain - the chain to get the key for.
     *
     * @return string
     */
    private static function getChainKey(NftablesChain $chain) : string
    {
        return self::getTableKey($chain->getTable()) . ' ' . $chain->getName();
    }


    # Accessors
    public function getResetMode() : NftablesRulesetResetMode { return $this->m_resetMode; }
}
