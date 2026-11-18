<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Internal\TableItemLib;
use Programster\Nftables\Maps\AnonymousMap;
use Programster\Nftables\Maps\NamedMap;
use Programster\Nftables\Tables\ReferencesTableItems;

/**
 * Looks a key up in a map, and stands for the value it maps to, e.g. tcp dport map @forwards, as the address of a
 * DnatStatement (see DnatStatement::createFromMap()), or the value of a MangleStatement. A packet whose key isn't in
 * the map doesn't match the rule. Get one from NamedMap::lookUp() or AnonymousMap::lookUp().
 */
final readonly class MapLookupExpression implements Expression, ReferencesTableItems
{
    private Expression $m_key;
    private NamedMap|AnonymousMap $m_map;


    /**
     * Create a map lookup.
     *
     * @param Expression $key - what to look up, e.g. a PayloadExpression for the packet's TCP destination port.
     *
     * @param NamedMap|AnonymousMap $map - the map to look it up in.
     */
    public function __construct(Expression $key, NamedMap|AnonymousMap $map)
    {
        $this->m_key = $key;
        $this->m_map = $map;
    }


    public function toJsonValue() : array
    {
        $data = ($this->m_map instanceof NamedMap) ? "@{$this->m_map->getName()}" : $this->m_map->toJsonValue();
        return ["map" => ["key" => $this->m_key->toJsonValue(), "data" => $data]];
    }


    public function getReferencedItems() : TableItemCollection
    {
        $items = TableItemLib::collectReferences($this->m_key);

        if ($this->m_map instanceof NamedMap)
        {
            $items = $items->merge(new TableItemCollection($this->m_map));
        }

        return $items;
    }
}
