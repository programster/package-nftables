<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\ChainLib;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Flowtable;
use Programster\Nftables\ReferencesTableItems;

/**
 * Offloads the packet's connection to a flowtable (flow add @fastpath), so its later packets take the flowtable's fast
 * path. Only works in a filter chain on the forward hook, and only for TCP and UDP, so match those first, as
 * RuleFactory::createFlowOffload() does. Adding a rule with one to a Ruleset adds the flowtable as well.
 */
final readonly class FlowOffloadStatement implements Statement, ReferencesTableItems, ChainRestricted
{
    private Flowtable $m_flowtable;


    public function __construct(Flowtable $flowtable)
    {
        $this->m_flowtable = $flowtable;
    }


    public function toArray() : array
    {
        return ["flow" => ["op" => "add", "flowtable" => "@{$this->m_flowtable->getName()}"]];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return new TableItemCollection([$this->m_flowtable]);
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        ChainLib::assertChainIs($chain, ChainType::FILTER, "offload to a flowtable", ChainHook::FORWARD);
    }


    # Accessors
    public function getFlowtable() : Flowtable { return $this->m_flowtable; }
}
