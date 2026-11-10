<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\AnonymousVerdictMap;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\NamedVerdictMap;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\TableItemLib;

/**
 * Looks a key up in a verdict map, and applies the verdict it maps to, e.g.
 * tcp dport vmap { 22 : accept, 80 : jump web }. nftables finds the key in one lookup, however many elements there
 * are, rather than trying a rule per key in turn. A packet whose key isn't in the map carries on with the next rule.
 * Get one from NamedVerdictMap::lookUp() or AnonymousVerdictMap::lookUp().
 */
final readonly class VerdictMapStatement implements Statement, ReferencesTableItems
{
    private Expression $m_key;
    private NamedVerdictMap|AnonymousVerdictMap $m_map;


    /**
     * Create a verdict map statement.
     *
     * @param Expression $key - what to look up, e.g. a PayloadExpression for the packet's TCP destination port.
     *
     * @param NamedVerdictMap|AnonymousVerdictMap $map - the map to look it up in.
     */
    public function __construct(Expression $key, NamedVerdictMap|AnonymousVerdictMap $map)
    {
        $this->m_key = $key;
        $this->m_map = $map;
    }


    public function toArray() : array
    {
        $data = ($this->m_map instanceof NamedVerdictMap) ? "@{$this->m_map->getName()}" : $this->m_map->toJsonValue();
        return ["vmap" => ["key" => $this->m_key->toJsonValue(), "data" => $data]];
    }


    public function getReferencedItems() : TableItemCollection
    {
        $items = TableItemLib::collectReferences($this->m_key);

        // A named map's chains are added along with the map.
        if ($this->m_map instanceof NamedVerdictMap)
        {
            $items->add($this->m_map);
        }
        else
        {
            TableItemLib::addAll($items, $this->m_map->getReferencedItems());
        }

        return $items;
    }
}
