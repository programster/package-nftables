<?php

declare(strict_types=1);

namespace Programster\Nftables;

use JsonException;
use JsonSerializable;
use Programster\Nftables\Chains\BaseChain;
use Programster\Nftables\Chains\Chain;
use Programster\Nftables\Chains\EmptyChain;
use Programster\Nftables\Collections\EmptyChainCollection;
use Programster\Nftables\Collections\EmptyTableCollection;
use Programster\Nftables\Collections\RuleCollection;
use Programster\Nftables\Collections\TableEntry;
use Programster\Nftables\Collections\TableItemEntry;
use Programster\Nftables\Collections\TableItemMap;
use Programster\Nftables\Collections\TableMap;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Exceptions\ConflictException;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;
use Programster\Nftables\Internal\Compatibility;
use Programster\Nftables\Internal\TableItemLib;
use Programster\Nftables\Tables\Table;
use Programster\Nftables\Tables\TableItem;

/**
 * A complete nftables ruleset, ready to be loaded with "nft --json --file". It takes care of the things that are easy
 * to get wrong when putting the JSON together by hand:
 *
 * - the metainfo block always comes first.
 *
 * - it clears out the old version of the rules first, in the same transaction as the load, so reloading never stacks
 * up duplicate rules, and a ruleset that fails to load leaves the previous rules in place.
 *
 * - tables come first, then chains, then everything else in a table (sets, maps, flowtables and named objects), then
 * rules, so nothing refers to something that doesn't exist yet.
 *
 * Its rules bring everything they need: their chains and tables, and any chains, sets, maps, flowtables and named
 * objects they use (including the chains a verdict map jumps to). The only things that need passing in as well are
 * the rare ones nothing else brings: a base chain with no rules, kept for its policy, and a table with nothing in it.
 * Anything else that no rule uses would do nothing, so it can't be passed in at all.
 *
 * - it throws if it's given something its target's nft can't load, or would silently ignore, so the problem shows
 * up here rather than on the server. See NftablesTarget.
 *
 * Everything is passed to the constructor, and it can't be changed afterwards.
 */
final readonly class Ruleset implements JsonSerializable
{
    private NftablesTarget $m_target;
    private RulesetResetMode $m_resetMode;

    // Keyed by getTableKey().
    private TableMap $m_tables;

    // The chains, sets, maps, flowtables and named objects, keyed by getItemKey().
    private TableItemMap $m_items;

    // In the order nftables evaluates them in.
    private RuleCollection $m_rules;


    /**
     * Create a ruleset.
     *
     * @param RuleCollection $rules - the rules, in the order they should be matched. Everything they use (their chains
     * and tables, and any chains, sets, maps, flowtables and named objects they refer to) is added with them. It can be
     * empty, e.g. for a ruleset of only chains.
     *
     * @param NftablesTarget $target - where the ruleset will be loaded: an operating system release (e.g. DEBIAN_12)
     * or an nft version. Anything that target can't load throws. Defaults to the oldest supported target (nft 0.9.8,
     * as in Debian 11), so the ruleset loads anywhere, and only features every target has can be used.
     *
     * @param RulesetResetMode $resetMode - what to clear out before loading this ruleset. Defaults to only replacing
     * the tables this ruleset defines, leaving any tables created by other software (e.g. fail2ban or Docker) alone.
     * Pass FLUSH_ENTIRE_RULESET to wipe everything on the machine first.
     *
     * @param EmptyChainCollection $emptyChains - optionally, base chains with no rules, kept just for their policy,
     * e.g. a forward chain with a drop policy on a machine that mustn't route anything. Their tables are added with
     * them. A chain with rules doesn't need this, as its rules bring it.
     *
     * @param EmptyTableCollection $emptyTables - optionally, tables with nothing in them, e.g. to empty a table that's
     * no longer used. A table with anything in it doesn't need this, as its chains and other items bring it.
     *
     * @throws ConflictException - if two different tables, or two different items of the same kind, share a name in
     * the same place (sets and maps share their names in nftables), an empty chain has the same name as a chain with
     * rules in its table, or an empty table has the same family and name as a table that's in use. The same table or
     * item twice is fine.
     *
     * @throws UnsupportedFeatureException - if the target can't load a rule, table or item.
     */
    public function __construct(
        RuleCollection $rules,
        NftablesTarget $target = NftablesTarget::NFTABLES_0_9_8,
        RulesetResetMode $resetMode = RulesetResetMode::REPLACE_OWN_TABLES,
        EmptyChainCollection $emptyChains = new EmptyChainCollection(),
        EmptyTableCollection $emptyTables = new EmptyTableCollection(),
    )
    {
        $this->m_target = $target;
        $this->m_resetMode = $resetMode;
        $tableMap = new TableMap();
        $itemMap = new TableItemMap();

        // The keys of the chains that have rules, as an empty chain can't have the same name as one of them.
        $chainsWithRules = [];

        foreach ($rules as $rule)
        {
            Compatibility::assertSupported($rule->toArray(), $target);
            $this->addItemTo($tableMap, $itemMap, $rule->getChain());
            $chainsWithRules[] = self::getItemKey($rule->getChain());

            foreach ($rule->getReferencedItems() as $referencedItem)
            {
                $this->addItemTo($tableMap, $itemMap, $referencedItem);
            }
        }

        foreach ($emptyChains as $emptyChain)
        {
            $chain = self::createChain($emptyChain);

            if (in_array(self::getItemKey($chain), $chainsWithRules, true))
            {
                $where = "{$chain->getTable()->getFamily()->value} {$chain->getTable()->getName()}";
                $name = $chain->getName();
                $message = "The empty chain {$name} in table {$where} has the same name as a chain with rules.";
                throw new ConflictException($message);
            }

            $this->addItemTo($tableMap, $itemMap, $chain);
        }

        // An empty table can't also be one that's in use, as it would be in the ruleset twice: once with its contents,
        // and once without them.
        $tablesInUse = $tableMap->keys();

        foreach ($emptyTables as $emptyTable)
        {
            $table = new Table($emptyTable->getName(), $emptyTable->getFamily());

            if (in_array(self::getTableKey($table), $tablesInUse, true))
            {
                $description = "{$table->getFamily()->value} {$table->getName()}";
                $message = "The empty table {$description} is also in use. Leave it out of the empty tables.";
                throw new ConflictException($message);
            }

            $this->addTableTo($tableMap, $table);
        }

        $this->m_tables = $tableMap;
        $this->m_items = $itemMap;
        $this->m_rules = $rules;
    }


    /**
     * Get the ruleset in the form nftables expects, ready to be JSON encoded.
     *
     * @return array
     */
    public function toArray() : array
    {
        // Only the schema version is needed. nft checks it isn't newer than it understands.
        $items = [["metainfo" => ["json_schema_version" => 1]]];

        if ($this->m_resetMode === RulesetResetMode::FLUSH_ENTIRE_RULESET)
        {
            $items[] = ["flush" => ["ruleset" => null]];
        }
        else
        {
            // Adding the table first means the delete can't fail if the table doesn't exist yet (e.g. on first boot).
            foreach ($this->m_tables as $table)
            {
                $items[] = ["add" => $table->toIdentifierArray()];
                $items[] = ["delete" => $table->toIdentifierArray()];
            }
        }

        // Chains come before the other items, as a verdict map's elements can jump to them.
        $chains = [];
        $otherItems = [];

        foreach ($this->m_items as $item)
        {
            if ($item instanceof Chain)
            {
                $chains[] = $item;
            }
            else
            {
                $otherItems[] = $item;
            }
        }

        $definitions = [...$this->m_tables->values(), ...$chains, ...$otherItems, ...$this->m_rules];

        foreach ($definitions as $definition)
        {
            $items[] = $definition->toArray();
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
     * Add a table to a map of tables, unless the same table is already in it.
     *
     * @param TableMap $tables - the tables, keyed by getTableKey().
     *
     * @param Table $table - the table to add.
     *
     * @return void
     *
     * @throws ConflictException - if a table with the same family and name, but different flags, is already in it.
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it.
     */
    private function addTableTo(TableMap $tables, Table $table) : void
    {
        Compatibility::assertSupported($table->toArray(), $this->m_target);
        $key = self::getTableKey($table);

        if ($tables->containsKey($key))
        {
            self::assertNoConflict($tables->get($key), $table->toArray(), "table {$table->getName()}");
        }
        else
        {
            $tables->put(new TableEntry($key, $table));
        }
    }


    /**
     * Add an item, its table, and anything it refers to (e.g. the chains a verdict map jumps to), to maps of them,
     * unless they're already in them.
     *
     * @param TableMap $tables - the tables, keyed by getTableKey().
     *
     * @param TableItemMap $items - the items, keyed by getItemKey().
     *
     * @param TableItem $item - the item to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different item of the same kind and name, or a different table, is already in
     * them.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or its table.
     */
    private function addItemTo(TableMap $tables, TableItemMap $items, TableItem $item) : void
    {
        Compatibility::assertSupported($item->toArray(), $this->m_target);
        $key = self::getItemKey($item);

        if ($items->containsKey($key))
        {
            self::assertNoConflict($items->get($key), $item->toArray(), TableItemLib::describe($item));
        }

        $this->addTableTo($tables, $item->getTable());
        $items->put(new TableItemEntry($key, $item));

        foreach (TableItemLib::collectReferencesOfItem($item) as $referencedItem)
        {
            $this->addItemTo($tables, $items, $referencedItem);
        }
    }


    /**
     * Check that what's already stored where a new table or item will go is the same as it.
     *
     * @param Table|TableItem $existing - what's already stored there.
     *
     * @param array $definition - the new table or item's toArray().
     *
     * @param string $description - what the new table or item is, for the message, e.g. "chain input".
     *
     * @return void
     *
     * @throws ConflictException - if something different is already stored there.
     */
    private static function assertNoConflict(
        Table|TableItem $existing,
        array $definition,
        string $description,
    ) : void
    {
        if ($existing->toArray() !== $definition)
        {
            throw new ConflictException("A different {$description} has already been added in the same place.");
        }
    }


    /**
     * Create the base chain an empty chain stands for, which only the ruleset ever has.
     *
     * @param EmptyChain $emptyChain - the empty chain.
     *
     * @return BaseChain
     */
    private static function createChain(EmptyChain $emptyChain) : BaseChain
    {
        return new BaseChain(
            $emptyChain->getName(),
            $emptyChain->getTable(),
            $emptyChain->getType(),
            $emptyChain->getHook(),
            $emptyChain->getPriority(),
            $emptyChain->getPolicy(),
            $emptyChain->getDevice(),
        );
    }


    /**
     * Get the key an item is stored under, which is unique to its kind, table and name. Sets and maps (of both kinds)
     * share a key, as they share their names in nftables. Every other kind has names of its own.
     *
     * @param TableItem $item - the item.
     *
     * @return string
     */
    private static function getItemKey(TableItem $item) : string
    {
        $kind = array_key_first($item->toArray());
        $namespace = ($kind === "map") ? "set" : $kind;
        return "{$namespace} " . self::getTableKey($item->getTable()) . " {$item->getName()}";
    }


    /**
     * Get the key a table is stored under, which is unique to its family and name.
     *
     * @param Table $table - the table.
     *
     * @return string
     */
    private static function getTableKey(Table $table) : string
    {
        return $table->getFamily()->value . " " . $table->getName();
    }


    # Accessors
    public function getTarget() : NftablesTarget { return $this->m_target; }
    public function getResetMode() : RulesetResetMode { return $this->m_resetMode; }
}
