<?php

namespace Programster\Nftables;

use JsonSerializable;
use Programster\Nftables\Enums\NftablesFamily;

readonly class NftablesTable implements JsonSerializable
{
    public function __construct(
        private string         $name,
        private NftablesFamily $family
    )
    {

    }


    public function toArray() : array
    {
        return [
            "table" => [
                "family" => $this->family->value,
                "name" =>  $this->name,
            ]
        ];
    }

    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }


    public function getName() : string { return $this->name; }
    public function getFamily() : NftablesFamily { return $this->family; }
}
