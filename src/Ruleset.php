<?php

declare(strict_types=1);

namespace Programster\Nftables;

use JsonException;
use JsonSerializable;
use Programster\Nftables\Collections\RuleCollection;
use Programster\Nftables\Collections\TableItemMap;
use Programster\Nftables\Collections\TableMap;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Enums\RulesetResetMode;
use Programster\Nftables\Exceptions\ConflictException;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;
use Programster\Nftables\Objects\NamedObject;

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
 * Adding a rule adds everything it needs: its chain and table, and any chains, sets, maps, flowtables and named objects
 * it uses (including the chains a verdict map jumps to). Only items that no rule uses (e.g. a chain that exists just
 * for its drop policy) need adding explicitly.
 *
 * - it throws if it's given something its target's nft can't load, or would silently ignore, so the problem shows
 * up here rather than on the server. See NftablesTarget.
 *
 * This is mutable by design, as it's built up one item at a time.
 */
final class Ruleset implements JsonSerializable
{
    private readonly NftablesTarget $m_target;
    private readonly RulesetResetMode $m_resetMode;

    // Keyed by getTableKey(). Replaced with an updated copy whenever something is added, so a problem part way
    // through leaves the ruleset as it was.
    private TableMap $m_tables;

    // The chains, sets, maps, flowtables and named objects, keyed by getItemKey(). Replaced as $m_tables is.
    private TableItemMap $m_items;

    // In the order they were added, which is the order nftables evaluates them in.
    private readonly RuleCollection $m_rules;


    /**
     * Create an empty ruleset.
     *
     * @param NftablesTarget $target - where the ruleset will be loaded: an operating system release (e.g. DEBIAN_12)
     * or an nft version. Adding anything that target can't load throws. Defaults to the oldest supported target (nft
     * 0.9.8, as in Debian 11), so the ruleset loads anywhere, and only features every target has can be used.
     *
     * @param RulesetResetMode $resetMode - what to clear out before loading this ruleset. Defaults to only replacing
     * the tables this ruleset defines, leaving any tables created by other software (e.g. fail2ban or Docker) alone.
     * Pass FLUSH_ENTIRE_RULESET to wipe everything on the machine first.
     */
    public function __construct(
        NftablesTarget $target = NftablesTarget::NFTABLES_0_9_8,
        RulesetResetMode $resetMode = RulesetResetMode::REPLACE_OWN_TABLES,
    )
    {
        $this->m_target = $target;
        $this->m_resetMode = $resetMode;
        $this->m_tables = new TableMap();
        $this->m_items = new TableItemMap();
        $this->m_rules = new RuleCollection();
    }


    /**
     * Add a table. Adding the same table again has no effect.
     *
     * @param Table $table - the table to add.
     *
     * @return void
     *
     * @throws ConflictException - if a table with the same family and name, but different flags, was already added.
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it.
     */
    public function addTable(Table $table) : void
    {
        $tables = clone $this->m_tables;
        $this->addTableTo($tables, $table);
        $this->m_tables = $tables;
    }


    /**
     * Add a named set, and the table it belongs to. Adding the same set again has no effect.
     *
     * @param NamedSet $set - the set to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different set with the same name was already added to its table, or a
     * different table with the same name as its table.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or its table.
     */
    public function addSet(NamedSet $set) : void
    {
        $this->addItems($set);
    }


    /**
     * Add a chain, and the table it belongs to. Adding the same chain again has no effect.
     *
     * @param Chain $chain - the chain to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different chain with the same name was already added to its table, or a
     * different table with the same name as its table.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or its table.
     */
    public function addChain(Chain $chain) : void
    {
        $this->addItems($chain);
    }


    /**
     * Add a map or verdict map, the table it belongs to, and any chains a verdict map jumps or goes to. Adding the same
     * map again has no effect.
     *
     * @param NamedMap|NamedVerdictMap $map - the map to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different set or map with the same name was already added to its table (sets
     * and maps share their names in nftables), or anything else it adds conflicts with something already added.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or anything it adds.
     */
    public function addMap(NamedMap|NamedVerdictMap $map) : void
    {
        $this->addItems($map);
    }


    /**
     * Add a flowtable, and the table it belongs to. Adding the same flowtable again has no effect.
     *
     * @param Flowtable $flowtable - the flowtable to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different flowtable with the same name was already added to its table, or a
     * different table with the same name as its table.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or its table.
     */
    public function addFlowtable(Flowtable $flowtable) : void
    {
        $this->addItems($flowtable);
    }


    /**
     * Add a named object (e.g. a NamedCounter, so its count can be read with "nft list counters"), and the table it
     * belongs to. Adding the same object again has no effect.
     *
     * @param NamedObject $object - the object to add.
     *
     * @return void
     *
     * @throws ConflictException - if a different object of the same kind and name was already added to its table, or a
     * different table with the same name as its table.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load it, or its table.
     */
    public function addObject(NamedObject $object) : void
    {
        $this->addItems($object);
    }


    /**
     * Add one or more rules to the end of the ruleset, along with everything they use: their chains and tables, and any
     * chains, sets, maps, flowtables and named objects they use. Rules are evaluated in the order they're added, so add
     * them in the order you want them to be matched.
     *
     * @param Rule ...$rules - the rule(s) to add.
     *
     * @return void
     *
     * @throws ConflictException - if anything a rule uses conflicts with something already added, or with something
     * another of the rules uses. None of the rules are added if this is thrown.
     *
     * @throws UnsupportedFeatureException - if the ruleset's target can't load a rule, or anything it uses. None of the
     * rules are added if this is thrown.
     */
    public function addRule(Rule ...$rules) : void
    {
        // Work on copies, so a problem part way through doesn't leave only some of the rules added.
        $tables = clone $this->m_tables;
        $items = clone $this->m_items;

        foreach ($rules as $rule)
        {
            Compatibility::assertSupported($rule->toArray(), $this->m_target);
            $this->addItemTo($tables, $items, $rule->getChain());

            foreach ($rule->getReferencedItems() as $referencedItem)
            {
                $this->addItemTo($tables, $items, $referencedItem);
            }
        }

        $this->m_tables = $tables;
        $this->m_items = $items;

        foreach ($rules as $rule)
        {
            $this->m_rules->add($rule);
        }
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

        $definitions = [...$this->m_tables->toArray(), ...$chains, ...$otherItems, ...$this->m_rules->toArray()];

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
        $existing = $tables->get($key);
        self::assertNoConflict($existing, $table->toArray(), "table {$table->getName()}");
        $tables->put($key, $table);
    }


    /**
     * Add items to the ruleset, along with their tables and anything they refer to, all or nothing.
     *
     * @param TableItem ...$items - the items.
     *
     * @return void
     *
     * @throws ConflictException - if anything conflicts with something already added.
     * @throws UnsupportedFeatureException - if the ruleset's target can't load anything.
     */
    private function addItems(TableItem ...$items) : void
    {
        $tables = clone $this->m_tables;
        $addedItems = clone $this->m_items;

        foreach ($items as $item)
        {
            $this->addItemTo($tables, $addedItems, $item);
        }

        $this->m_tables = $tables;
        $this->m_items = $addedItems;
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
        self::assertNoConflict($items->get($key), $item->toArray(), TableItemLib::describe($item));
        $this->addTableTo($tables, $item->getTable());
        $items->put($key, $item);

        foreach (TableItemLib::collectReferencesOfItem($item) as $referencedItem)
        {
            $this->addItemTo($tables, $items, $referencedItem);
        }
    }


    /**
     * Check that what's already stored where a new table or item will go, if anything, is the same as it.
     *
     * @param Table|TableItem|null $existing - what's already stored there, or null if nothing is.
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
        Table|TableItem|null $existing,
        array $definition,
        string $description,
    ) : void
    {
        if ($existing !== null && $existing->toArray() !== $definition)
        {
            throw new ConflictException("A different {$description} has already been added in the same place.");
        }
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
