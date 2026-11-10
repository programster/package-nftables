<?php

declare(strict_types=1);

namespace Programster\Nftables;

use IPLib\Address\Type;
use IPLib\Factory;
use IPLib\Range\Subnet;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;

/**
 * Checks for IP addresses, CIDRs and ports.
 */
final class NetworkLib
{
    private const MIN_PORT = 1;
    private const MAX_PORT = 65535;


    private function __construct()
    {
    }


    /**
     * Check whether a string is a single IPv4 or IPv6 address, e.g. 192.168.1.6 or fd00::1.
     *
     * @param string $address - the string to check.
     *
     * @return bool
     */
    public static function isIpAddress(string $address) : bool
    {
        return Factory::parseAddressString($address) !== null;
    }


    /**
     * Check whether a string is a valid CIDR, such as 192.168.1.6/24. Use isValidNetworkCidr() instead to also check
     * that it's a network, as nftables needs.
     *
     * @param string $cidr - the string to check.
     *
     * @return bool
     */
    public static function isValidCidr(string $cidr) : bool
    {
        return str_contains($cidr, "/") && Subnet::parseString($cidr) !== null;
    }


    /**
     * Check whether a string is a network CIDR: one whose host bits are all zero, such as 192.168.0.0/24 (and not
     * 192.168.0.1/24), which is what nftables needs.
     *
     * @param string $cidr - the string to check.
     *
     * @return bool
     */
    public static function isValidNetworkCidr(string $cidr) : bool
    {
        $result = false;

        if (self::isValidCidr($cidr))
        {
            $subnet = Subnet::parseString($cidr);
            $address = Factory::parseAddressString(explode("/", $cidr)[0]);

            $result = (
                   $address !== null
                && $subnet->getStartAddress()->getComparableString() === $address->getComparableString()
            );
        }

        return $result;
    }


    /**
     * Check that a string is a network CIDR, with a message that says what's wrong if it isn't.
     *
     * @param string $cidr - the string to check.
     *
     * @return void
     *
     * @throws InvalidAddressException - if it isn't a network CIDR.
     */
    public static function assertValidNetworkCidr(string $cidr) : void
    {
        if (!self::isValidNetworkCidr($cidr))
        {
            if (self::isValidCidr($cidr))
            {
                $network = Subnet::parseString($cidr)->toString();
                throw new InvalidAddressException("{$cidr} has host bits set. Did you mean the network {$network}?");
            }
            else
            {
                throw new InvalidAddressException("{$cidr} isn't a valid CIDR.");
            }
        }
    }


    /**
     * Get whether an IP address or CIDR is IPv4 or IPv6.
     *
     * @param string $addressOrCidr - an IP address, e.g. 10.0.0.1, or a CIDR, e.g. fd00::/8.
     *
     * @return IpVersion
     *
     * @throws InvalidAddressException - if it's neither an IP address nor a CIDR.
     */
    public static function getIpVersion(string $addressOrCidr) : IpVersion
    {
        $parsed = str_contains($addressOrCidr, "/")
            ? Subnet::parseString($addressOrCidr)
            : Factory::parseAddressString($addressOrCidr);

        if ($parsed === null)
        {
            throw new InvalidAddressException("{$addressOrCidr} isn't an IP address or CIDR.");
        }

        return ($parsed->getAddressType() === Type::T_IPv6) ? IpVersion::IPV6 : IpVersion::IPV4;
    }


    /**
     * Check that a port number is between 1 and 65535.
     *
     * @param int $port - the port to check.
     *
     * @return void
     *
     * @throws BadArgumentException - if it isn't.
     */
    public static function assertValidPort(int $port) : void
    {
        if ($port < self::MIN_PORT || $port > self::MAX_PORT)
        {
            throw new BadArgumentException("A port must be between 1 and 65535, not {$port}.");
        }
    }
}
