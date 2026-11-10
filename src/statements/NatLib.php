<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\NatFlag;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Expressions\MapLookupExpression;
use Programster\Nftables\NetworkLib;
use Programster\Nftables\PortRange;

/**
 * Builds the JSON shared by the NAT statements.
 *
 * @internal
 */
final class NatLib
{
    private function __construct()
    {
    }


    /**
     * Build the body of a NAT statement.
     *
     * @param string $address - the address to translate to, or "" for none (masquerade and redirect).
     *
     * @param int|PortRange|null $port - the port or ports to translate to, or null to leave the port alone.
     *
     * @param NatFlag ...$flags - the statement's flags.
     *
     * @return array - the body, which is empty if there's nothing in it.
     *
     * @throws InvalidAddressException - if the address isn't an IP address.
     * @throws BadArgumentException - if the port isn't between 1 and 65535.
     */
    public static function createBody(string $address, int|PortRange|null $port, NatFlag ...$flags) : array
    {
        $body = [];

        if ($address !== "")
        {
            // The family is required in inet tables, and harmless in the others.
            $body["addr"] = $address;
            $body["family"] = NetworkLib::getIpVersion($address)->value;
        }

        if (is_int($port))
        {
            NetworkLib::assertValidPort($port);
            $body["port"] = $port;
        }
        elseif ($port instanceof PortRange)
        {
            $body["port"] = $port->toJsonValue();
        }

        return [...$body, ...self::createFlags(...$flags)];
    }


    /**
     * Build the body of a NAT statement that looks its address (and optionally port) up in maps.
     *
     * @param IpVersion $ipVersion - the IP version of the addresses.
     *
     * @param MapLookupExpression $address - the lookup that gives the address, or the address and port.
     *
     * @param MapLookupExpression|null $port - the lookup that gives the port, or null for none.
     *
     * @param NatFlag ...$flags - the statement's flags.
     *
     * @return array
     */
    public static function createMapBody(
        IpVersion $ipVersion,
        MapLookupExpression $address,
        ?MapLookupExpression $port,
        NatFlag ...$flags,
    ) : array
    {
        // The family is required in inet tables, and harmless in the others.
        $body = ["family" => $ipVersion->value, "addr" => $address->toJsonValue()];

        if ($port !== null)
        {
            $body["port"] = $port->toJsonValue();
        }

        return [...$body, ...self::createFlags(...$flags)];
    }


    /**
     * Build the flags part of a NAT statement's body.
     *
     * @param NatFlag ...$flags - the flags.
     *
     * @return array - empty if there are none.
     */
    private static function createFlags(NatFlag ...$flags) : array
    {
        $body = [];

        if (count($flags) > 0)
        {
            $body["flags"] = array_values(array_unique(array_column($flags, "value")));
        }

        return $body;
    }
}
