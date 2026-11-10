<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\SetFlagCollection;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Collections\VerdictMapElementCollection;
use Programster\Nftables\Enums\SetFlag;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\Statements\VerdictMapStatement;

/**
 * A named map from keys to verdicts, e.g. from a destination port to accept, drop, or a jump to the chain that handles
 * that service. A rule applies it with a VerdictMapStatement, which looks the packet's key up once, however many
 * elements there are, rather than trying a rule per key in turn. Like a NamedSet, it can be shared by several rules,
 * and its elements changed at runtime with "nft add element" without reloading the rules. For a fixed list used by one
 * rule, an AnonymousVerdictMap is simpler.
 *
 * Adding it to a Ruleset (or a rule that uses it) adds the chains its elements jump or go to as well.
 *
 * Reloading a Ruleset recreates its maps with only the elements given here, so elements added at runtime are lost.
 */
final readonly class NamedVerdictMap implements TableItem, ReferencesTableItems
{
    private Table $m_table;
    private string $m_name;

    // More than one for a concatenation.
    private SetTypeCollection $m_keyTypes;

    // Without duplicates.
    private SetFlagCollection $m_flags;

    private VerdictMapElementCollection $m_elements;


    /**
     * Create a named verdict map. Use create() and withElements().
     *
     * @param Table $table - the table the map belongs to.
     *
     * @param string $name - the map's name.
     *
     * @param SetTypeCollection $keyTypes - the type of the keys, or several for a concatenation.
     *
     * @param SetFlagCollection $flags - the map's flags.
     *
     * @param VerdictMapElement ...$elements - the initial elements.
     *
     * @throws BadArgumentException - if there's no key type, the name isn't valid, or an element's key is a range or
     * prefix and the map doesn't have the INTERVAL flag.
     *
     * @throws UnsuitableChainException - if an element jumps or goes to a chain in a different table.
     */
    private function __construct(
        Table $table,
        string $name,
        SetTypeCollection $keyTypes,
        SetFlagCollection $flags,
        VerdictMapElement ...$elements,
    )
    {
        NameLib::assertValidName($name, "map");
        $uniqueFlags = [];
        $keys = [];

        foreach ($flags as $flag)
        {
            $uniqueFlags[$flag->value] = $flag;
        }

        foreach ($elements as $element)
        {
            $keys[] = $element->getKey();
            TableItemLib::assertAllInTable($table, "A verdict map", $element->getReferencedItems());
        }

        if (count($keyTypes) === 0)
        {
            throw new BadArgumentException("A verdict map needs a key type.");
        }

        if (!isset($uniqueFlags[SetFlag::INTERVAL->value]) && ExpressionLib::isAnyInterval(...$keys))
        {
            throw new BadArgumentException("A map needs the INTERVAL flag to have ranges or prefixes as keys.");
        }

        $this->m_table = $table;
        $this->m_name = $name;
        // Copies, as collections can be changed, and the caller still has these ones.
        $this->m_keyTypes = new SetTypeCollection($keyTypes->toArray());
        $this->m_flags = new SetFlagCollection(array_values($uniqueFlags));
        $this->m_elements = new VerdictMapElementCollection(array_values($elements));
    }


    /**
     * Create an empty named verdict map. Add its initial elements with withElements().
     *
     * @param Table $table - the table the map belongs to. Only rules in the same table can use it.
     *
     * @param string $name - the map's name, which must be unique among the sets and maps in its table.
     *
     * @param SetType|SetTypeCollection $keyType - the type of the keys, or a collection of types for keys that are a
     * concatenation of values (e.g. an address and a port, as ConcatExpressions).
     *
     * @param SetFlag ...$flags - the map's flags. INTERVAL is needed for keys that are ranges or prefixes.
     *
     * @return NamedVerdictMap
     *
     * @throws BadArgumentException - if there's no key type, or the name is empty or too long.
     */
    public static function create(
        Table $table,
        string $name,
        SetType|SetTypeCollection $keyType,
        SetFlag ...$flags,
    ) : NamedVerdictMap
    {
        $keyTypes = ($keyType instanceof SetTypeCollection) ? $keyType : new SetTypeCollection([$keyType]);
        return new NamedVerdictMap($table, $name, $keyTypes, new SetFlagCollection($flags));
    }


    /**
     * Get a copy of the map with these initial elements, in place of any it had.
     *
     * @param VerdictMapElement ...$elements - the elements.
     *
     * @return NamedVerdictMap
     *
     * @throws BadArgumentException - if an element's key is a range or prefix and the map doesn't have the INTERVAL
     * flag.
     *
     * @throws UnsuitableChainException - if an element jumps or goes to a chain in a different table.
     */
    public function withElements(VerdictMapElement ...$elements) : NamedVerdictMap
    {
        return new NamedVerdictMap($this->m_table, $this->m_name, $this->m_keyTypes, $this->m_flags, ...$elements);
    }


    /**
     * Get a statement that looks a key up in the map, and applies the verdict it maps to. A packet whose key isn't in
     * the map carries on with the next rule.
     *
     * @param Expression $key - what to look up, e.g. a PayloadExpression for the packet's TCP destination port.
     *
     * @return VerdictMapStatement
     */
    public function lookUp(Expression $key) : VerdictMapStatement
    {
        return new VerdictMapStatement($key, $this);
    }


    public function toArray() : array
    {
        $keyTypes = $this->m_keyTypes->column("value");

        $map = [
            "family" => $this->m_table->getFamily()->value,
            "table" => $this->m_table->getName(),
            "name" => $this->m_name,
            "type" => (count($keyTypes) === 1) ? $keyTypes[0] : $keyTypes,
            "map" => "verdict",
        ];

        if (count($this->m_flags) > 0)
        {
            $map["flags"] = $this->m_flags->column("value");
        }

        if (count($this->m_elements) > 0)
        {
            $map["elem"] = [];

            foreach ($this->m_elements as $element)
            {
                $map["elem"][] = $element->toJsonValue();
            }
        }

        return ["map" => $map];
    }


    public function getReferencedItems() : TableItemCollection
    {
        $items = new TableItemCollection();

        foreach ($this->m_elements as $element)
        {
            TableItemLib::addAll($items, $element->getReferencedItems());
        }

        return $items;
    }


    # Accessors
    public function getTable() : Table { return $this->m_table; }
    public function getName() : string { return $this->m_name; }
}
