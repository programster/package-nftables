<?php

namespace Programster\Nftables;

use JsonSerializable;
use Programster\Nftables\Enums\NftablesFamily;


readonly class NftablesRule implements JsonSerializable
{
    private NftablesChain $m_chain;
    private array $m_expressions;



    public function __construct(NftablesChain $chain, array $expressions)
    {
        $this->m_chain = $chain;
        $this->m_expressions = $expressions;
    }


    public function toArray() : array
    {
        return [
            "rule" => [
                "family" => $this->m_chain->getTable()->getFamily()->value,
                "table" => $this->m_chain->getTable()->getName(),
                "chain" => $this->m_chain->getName(),
                "expr" => $this->m_expressions,
            ]
        ];
    }


    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }


    # Accessors
    public function getTable() : NftablesTable { return $this->m_chain->getTable(); }
    public function getChain() : NftablesChain { return $this->m_chain; }
    public function getFamily() : NftablesFamily { return $this->m_chain->getTable()->getFamily(); }
}