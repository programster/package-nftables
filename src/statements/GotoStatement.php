<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\RegularChain;

/**
 * Continues at the first rule of another chain, like a JumpStatement, but doesn't come back: when that chain ends,
 * evaluation carries on after the rule that jumped to this chain (or with the base chain's policy). Adding a rule with
 * one to a Ruleset adds the target chain as well.
 */
final readonly class GotoStatement implements Statement, ReferencesTableItems
{
    private RegularChain $m_target;


    public function __construct(RegularChain $target)
    {
        $this->m_target = $target;
    }


    public function toArray() : array
    {
        return ["goto" => ["target" => $this->m_target->getName()]];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return new TableItemCollection([$this->m_target]);
    }


    # Accessors
    public function getTarget() : RegularChain { return $this->m_target; }
}
