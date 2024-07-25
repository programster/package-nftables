<?php

namespace Programster\Nftables;


use JsonSerializable;
use Programster\Nftables\Enums\NftablesChainHook;
use Programster\Nftables\Enums\NftablesChainType;
use Programster\Nftables\Enums\NftablesPolicy;
use Programster\Nftables\Enums\NftablesPriority;

readonly class NftablesChain implements JsonSerializable
{
    public function __construct(
        private string            $name,
        private NftablesTable     $table,
        private NftablesChainType $type,
        private NftablesChainHook $hook,
        private NftablesPriority  $priority,
        private NftablesPolicy    $policy,
    )
    {

    }


    public function toArray() : array
    {
        return [
            "chain" => [
                "family" => $this->table->getFamily()->value,
                "table" => $this->table->getName(),
                "name" => $this->name,
                "type" => $this->type->value,
                "hook" => $this->hook->value,
                "prio" => $this->priority->value,
                "policy" => $this->policy->value,
            ]
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }


    public function getTable() : NftablesTable
    {
        return $this->table;
    }

    public function getName() : string
    {
        return $this->name;
    }


    public function getHook() : NftablesChainHook
    {
        return $this->hook;
    }

    public function getType() : NftablesChainType
    {
        return $this->type;
    }
}
