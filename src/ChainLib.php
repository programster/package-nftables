<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Exceptions\UnsuitableChainException;

/**
 * Checks that base chains suit the rules and statements put in them.
 *
 * @internal
 */
final class ChainLib
{
    private function __construct()
    {
    }


    /**
     * Check that a chain has a type, and one of some hooks.
     *
     * @param BaseChain $chain - the chain.
     *
     * @param ChainType $type - the type it needs.
     *
     * @param string $purpose - what needs it, for the message, e.g. "masquerade".
     *
     * @param ChainHook ...$hooks - the hooks it can be on.
     *
     * @return void
     *
     * @throws UnsuitableChainException - if it doesn't have the type, or one of the hooks.
     */
    public static function assertChainIs(BaseChain $chain, ChainType $type, string $purpose, ChainHook ...$hooks) : void
    {
        if ($chain->getType() !== $type || !in_array($chain->getHook(), $hooks, true))
        {
            $hookNames = implode(" or ", array_column($hooks, "value"));
            $needs = "a {$type->value} chain on the {$hookNames} hook";
            $actual = "a {$chain->getType()->value} chain on the {$chain->getHook()->value} hook";
            throw new UnsuitableChainException("A rule to {$purpose} needs {$needs}, but was given {$actual}.");
        }
    }


    /**
     * Check that a chain is in an IP family's table (ip, ip6 or inet), for something that only works on IP packets.
     *
     * @param Chain $chain - the chain.
     *
     * @param string $purpose - what needs it, for the message, e.g. "clamp the MSS".
     *
     * @return void
     *
     * @throws UnsuitableChainException - if it's in another family's table.
     */
    public static function assertIpFamily(Chain $chain, string $purpose) : void
    {
        $family = $chain->getTable()->getFamily();

        if (!in_array($family, [Family::IP, Family::IP6, Family::INET], true))
        {
            $message = "A rule to {$purpose} needs an ip, ip6 or inet table, not {$family->value}.";
            throw new UnsuitableChainException($message);
        }
    }
}
