<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Collections\VerdictMapElementCollection;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Statements\VerdictMapStatement;

/**
 * A verdict map written into the rule itself, e.g. { 22 : accept, 80 : jump web }, applied with a VerdictMapStatement.
 * For a map that's shared between rules, or changed without reloading, use a NamedVerdictMap instead.
 */
final readonly class AnonymousVerdictMap implements ReferencesTableItems
{
    private VerdictMapElementCollection $m_elements;


    /**
     * Create an anonymous verdict map.
     *
     * @param VerdictMapElement ...$elements - the elements. At least one is needed.
     *
     * @throws BadArgumentException - if there are no elements.
     */
    public function __construct(VerdictMapElement ...$elements)
    {
        if (count($elements) === 0)
        {
            throw new BadArgumentException("A verdict map needs at least one element.");
        }

        $this->m_elements = new VerdictMapElementCollection(array_values($elements));
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


    /**
     * Get the map in the form nftables expects.
     *
     * @return array
     */
    public function toJsonValue() : array
    {
        $elements = [];

        foreach ($this->m_elements as $element)
        {
            $elements[] = $element->toJsonValue();
        }

        return ["set" => $elements];
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
}
