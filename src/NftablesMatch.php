<?php

/*
 * A library for creating matches for rules
 */

namespace Programster\Nftables;

use Programster\Nftables\Enums\NftablesMatchOperator;

readonly class NftablesMatch implements \JsonSerializable
{
    public function __construct(
        private NftablesMatchOperator $operator,
        private array|string $left,
        private mixed $right
    )
    {
    }


    public function toArray() : array
    {
        return [
            "match" => [
                "op" => $this->operator->value,
                "left" => $this->left,
                "right" => $this->right,
            ]
        ];
    }


    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }


    public function getOperator() : NftablesMatchOperator { return $this->operator; }
    public function getLeft() : array { return $this->left; }
    public function getRight() : mixed { return $this->right; }
}