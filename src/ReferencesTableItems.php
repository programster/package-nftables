<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\TableItemCollection;

/**
 * Something that refers to chains, sets, maps, flowtables or named objects by name, e.g. a jump, or a match against a
 * named set. Adding a rule to a Ruleset adds everything it refers to as well, and a rule can only refer to items in its
 * own table.
 */
interface ReferencesTableItems
{
    /**
     * Get the items this refers to, including those referred to by anything inside it.
     *
     * @return TableItemCollection
     */
    public function getReferencedItems() : TableItemCollection;
}
