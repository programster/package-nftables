<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\NamedSet;
use Programster\Nftables\ReferencesTableItems;

/**
 * A reference to a named set, for matching against it, e.g. ip saddr @blocklist. Get one from NamedSet::getReference().
 * Adding a rule that uses one to a Ruleset adds the set as well.
 */
final readonly class SetReference implements Expression, ReferencesTableItems
{
    private NamedSet $m_set;


    public function __construct(NamedSet $set)
    {
        $this->m_set = $set;
    }


    public function toJsonValue() : string
    {
        return "@" . $this->m_set->getName();
    }


    public function getReferencedItems() : TableItemCollection
    {
        return new TableItemCollection([$this->m_set]);
    }


    # Accessors
    public function getSet() : NamedSet { return $this->m_set; }
}
