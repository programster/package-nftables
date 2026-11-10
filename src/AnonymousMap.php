<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\MapElementCollection;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\MapLookupExpression;

/**
 * A map written into the rule itself, e.g. { 0 : 10.0.0.1, 1 : 10.0.0.2 }, to look a key up in with a
 * MapLookupExpression. For a map that's shared between rules, or changed without reloading, use a NamedMap instead.
 *
 * Unlike a NamedMap, its values can be concatenations (e.g. an address and a port) from nft 1.0.2.
 */
final readonly class AnonymousMap
{
    private MapElementCollection $m_elements;


    /**
     * Create an anonymous map.
     *
     * @param MapElement ...$elements - the elements. At least one is needed.
     *
     * @throws BadArgumentException - if there are no elements.
     */
    public function __construct(MapElement ...$elements)
    {
        if (count($elements) === 0)
        {
            throw new BadArgumentException("A map needs at least one element.");
        }

        $this->m_elements = new MapElementCollection(array_values($elements));
    }


    /**
     * Get an expression that looks a key up in the map, to use the value it maps to. A packet whose key isn't in the
     * map doesn't match the rule.
     *
     * @param Expression $key - what to look up, e.g. a NumgenExpression, to spread connections over several machines.
     *
     * @return MapLookupExpression
     */
    public function lookUp(Expression $key) : MapLookupExpression
    {
        return new MapLookupExpression($key, $this);
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
}
