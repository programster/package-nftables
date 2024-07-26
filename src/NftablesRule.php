<?php

namespace Programster\Nftables;

use JsonSerializable;
use Programster\Nftables\Enums\NftablesFamily;


readonly class NftablesRule implements JsonSerializable
{
    public function __construct(
        private NftablesChain $chain,
        private array $expressions,
        private ?string $comment = null
    )
    {
    }


    public function toArray() : array
    {
        $arrayForm = [
            "rule" => [
                "family" => $this->chain->getTable()->getFamily()->value,
                "table" => $this->chain->getTable()->getName(),
                "chain" => $this->chain->getName(),
                "expr" => $this->expressions,
            ]
        ];

        if ($this->comment !== null)
        {
            $arrayForm["rule"]["comment"] = $this->comment;
        }

        return $arrayForm;
    }


    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }


    # Accessors
    public function getTable() : NftablesTable { return $this->chain->getTable(); }
    public function getChain() : NftablesChain { return $this->chain; }
    public function getFamily() : NftablesFamily { return $this->chain->getTable()->getFamily(); }
}