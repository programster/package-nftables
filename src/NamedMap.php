<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\MapElementCollection;
use Programster\Nftables\Collections\SetFlagCollection;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\Enums\SetFlag;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\Expressions\MapLookupExpression;

/**
 * A named map from keys to values, e.g. from the port a connection arrives on to the address of the machine to forward
 * it to. A rule looks a key up in it with a MapLookupExpression, e.g. to use as the address of a DnatStatement. Like a
 * NamedSet, it can be shared by several rules, and its elements changed at runtime with "nft add element" without
 * reloading the rules. For a fixed list used by one rule, an AnonymousMap is simpler.
 *
 * To map keys to verdicts (accept, drop, jump and so on), use a NamedVerdictMap instead.
 *
 * Reloading a Ruleset recreates its maps with only the elements given here, so elements added at runtime are lost.
 */
final readonly class NamedMap implements TableItem
{
    private Table $m_table;
    private string $m_name;

    // More than one for a concatenation.
    private SetTypeCollection $m_keyTypes;

    // More than one for a concatenation.
    private SetTypeCollection $m_valueTypes;

    // Without duplicates.
    private SetFlagCollection $m_flags;

    private MapElementCollection $m_elements;


    /**
     * Create a named map. Use create() and withElements().
     *
     * @param Table $table - the table the map belongs to.
     *
     * @param string $name - the map's name.
     *
     * @param SetTypeCollection $keyTypes - the type of the keys, or several for a concatenation.
     *
     * @param SetTypeCollection $valueTypes - the type of the values, or several for a concatenation.
     *
     * @param SetFlagCollection $flags - the map's flags.
     *
     * @param MapElement ...$elements - the initial elements.
     *
     * @throws BadArgumentException - if a type is missing, the name isn't valid, or an element's key is a range or
     * prefix and the map doesn't have the INTERVAL flag.
     */
    private function __construct(
        Table $table,
        string $name,
        SetTypeCollection $keyTypes,
        SetTypeCollection $valueTypes,
        SetFlagCollection $flags,
        MapElement ...$elements,
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
        }

        if (count($keyTypes) === 0 || count($valueTypes) === 0)
        {
            throw new BadArgumentException("A map needs a key type and a value type.");
        }

        if (!isset($uniqueFlags[SetFlag::INTERVAL->value]) && ExpressionLib::isAnyInterval(...$keys))
        {
            throw new BadArgumentException("A map needs the INTERVAL flag to have ranges or prefixes as keys.");
        }

        $this->m_table = $table;
        $this->m_name = $name;
        // Copies, as collections can be changed, and the caller still has these ones.
        $this->m_keyTypes = new SetTypeCollection($keyTypes->toArray());
        $this->m_valueTypes = new SetTypeCollection($valueTypes->toArray());
        $this->m_flags = new SetFlagCollection(array_values($uniqueFlags));
        $this->m_elements = new MapElementCollection(array_values($elements));
    }


    /**
     * Create an empty named map. Add its initial elements with withElements().
     *
     * @param Table $table - the table the map belongs to. Only rules in the same table can use it.
     *
     * @param string $name - the map's name, which must be unique among the sets and maps in its table.
     *
     * @param SetType|SetTypeCollection $keyType - the type of the keys, or a collection of types for keys that are a
     * concatenation of values (e.g. an address and a port, as ConcatExpressions).
     *
     * @param SetType|SetTypeCollection $valueType - the type of the values, or a collection of types for values that
     * are a concatenation, e.g. IPV4_ADDR and INET_SERVICE, to port forward to an address and port. A map whose values
     * are a concatenation needs nft 1.1.3 (or RHEL 9's), as older nft crashes on them, or silently drops the map. An
     * AnonymousMap of them only needs nft 1.0.2.
     *
     * @param SetFlag ...$flags - the map's flags. INTERVAL is needed for keys that are ranges or prefixes.
     *
     * @return NamedMap
     *
     * @throws BadArgumentException - if there's no key or value type, or the name is empty or too long.
     */
    public static function create(
        Table $table,
        string $name,
        SetType|SetTypeCollection $keyType,
        SetType|SetTypeCollection $valueType,
        SetFlag ...$flags,
    ) : NamedMap
    {
        $keyTypes = ($keyType instanceof SetTypeCollection) ? $keyType : new SetTypeCollection([$keyType]);
        $valueTypes = ($valueType instanceof SetTypeCollection) ? $valueType : new SetTypeCollection([$valueType]);
        return new NamedMap($table, $name, $keyTypes, $valueTypes, new SetFlagCollection($flags));
    }


    /**
     * Get a copy of the map with these initial elements, in place of any it had.
     *
     * @param MapElement ...$elements - the elements.
     *
     * @return NamedMap
     *
     * @throws BadArgumentException - if an element's key is a range or prefix and the map doesn't have the INTERVAL
     * flag.
     */
    public function withElements(MapElement ...$elements) : NamedMap
    {
        $types = [$this->m_keyTypes, $this->m_valueTypes];
        [$keyTypes, $valueTypes] = $types;
        return new NamedMap($this->m_table, $this->m_name, $keyTypes, $valueTypes, $this->m_flags, ...$elements);
    }


    /**
     * Get an expression that looks a key up in the map, e.g. the packet's destination port, to use the value it maps
     * to. A packet whose key isn't in the map doesn't match the rule.
     *
     * @param Expression $key - what to look up, e.g. a PayloadExpression for the packet's TCP destination port.
     *
     * @return MapLookupExpression
     */
    public function lookUp(Expression $key) : MapLookupExpression
    {
        return new MapLookupExpression($key, $this);
    }


    public function toArray() : array
    {
        $keyTypes = $this->m_keyTypes->column("value");
        $valueTypes = $this->m_valueTypes->column("value");

        $map = [
            "family" => $this->m_table->getFamily()->value,
            "table" => $this->m_table->getName(),
            "name" => $this->m_name,
            "type" => (count($keyTypes) === 1) ? $keyTypes[0] : $keyTypes,
            "map" => (count($valueTypes) === 1) ? $valueTypes[0] : $valueTypes,
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


    # Accessors
    public function getTable() : Table { return $this->m_table; }
    public function getName() : string { return $this->m_name; }
}
