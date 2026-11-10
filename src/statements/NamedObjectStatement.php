<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Objects\NamedObject;
use Programster\Nftables\Objects\NamedSynproxy;
use Programster\Nftables\ReferencesTableItems;

/**
 * Uses a named object for the packet: adds it to a NamedCounter, checks it against a NamedQuota or NamedLimit, passes
 * it through a NamedSynproxy, gives its connection a CtHelper or CtTimeout, or gives it a Secmark. Get one from the
 * object's createStatement(). Adding a rule with one to a Ruleset adds the object as well.
 */
final readonly class NamedObjectStatement implements Statement, ReferencesTableItems, ChainRestricted
{
    private NamedObject $m_object;


    public function __construct(NamedObject $object)
    {
        $this->m_object = $object;
    }


    public function toArray() : array
    {
        return [array_key_first($this->m_object->toArray()) => $this->m_object->getName()];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return new TableItemCollection([$this->m_object]);
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        if ($this->m_object instanceof NamedSynproxy)
        {
            $this->m_object->getSynproxy()->assertSuitsChain($chain);
        }
    }


    # Accessors
    public function getObject() : NamedObject { return $this->m_object; }
}
