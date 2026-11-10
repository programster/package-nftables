<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\RegularChain;

/**
 * Continues at the first rule of another chain. When that chain ends (or returns), evaluation carries on with the rule
 * after this one. Adding a rule with one to a Ruleset adds the target chain as well.
 */
final readonly class JumpStatement implements Statement, ReferencesTableItems
{
    private RegularChain $m_target;


    public function __construct(RegularChain $target)
    {
        $this->m_target = $target;
    }


    public function toArray() : array
    {
        return ["jump" => ["target" => $this->m_target->getName()]];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return new TableItemCollection([$this->m_target]);
    }


    # Accessors
    public function getTarget() : RegularChain { return $this->m_target; }
}
