<?php

/*
 * A factory for creating NftablesMatch objects
 */

namespace Programster\Nftables;


use IPLib\Factory;
use IPLib\Range\Subnet;
use Programster\Nftables\Enums\NftablesConnectionState;
use Programster\Nftables\Enums\NftablesMatchOperator;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Exceptions\ExceptionConnectionStateRequired;
use Programster\Nftables\Exceptions\ExceptionInvalidNetworkCidr;
use Programster\Nftables\Exceptions\ExceptionPortRequired;

readonly class NftablesMatchFactory
{
    /**
     * Create a "match" for expressions, for matching against a port number and protocol (tcp/udp etc.).
     * @param Protocol $protocol - unsure if I could allow null on this in order to remove it in order to match both
     * tcp and udp traffic etc.
     * @param int $ports - any number of ports to match against. Must provide at least one.
     * @return array[]
     * @throws ExceptionPortRequired
     */
    public static function createMatchDestinationPorts(Protocol $protocol, int ...$ports) : NftablesMatch
    {
        $ports = array_unique($ports);

        if (count($ports) === 0)
        {
            throw new ExceptionPortRequired();
        }

        $left = [
            "payload" => [
                "protocol" => $protocol->value,
                "field" => "dport"
            ]
        ];

        if (count($ports) === 1)
        {
            $right = array_pop($ports);
        }
        else
        {
            $right = [
                "set" => $ports
            ];
        }

        return new NftablesMatch(NftablesMatchOperator::EQUALS, $left, $right);
    }


    /**
     * Create a match against a port range. E.g. 5000-6000
     * @param Protocol $protocol - the type of traffic (TCP/UDP)
     * @param PortRange $portRange - the range of ports to match against.
     * @return array[]
     */
    public static function createMatchDestinationPortRange(Protocol $protocol, PortRange $portRange) : NftablesMatch
    {
        $left = [
            "payload" => [
                "protocol" => $protocol->value,
                "field" => "dport"
            ]
        ];

        $right = [
            "range" => [
                $portRange->minPort,
                $portRange->maxPort,
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::EQUALS, $left, $right);
    }


    /**
     * Create a match rule for the name of an input interface. E.g. "lo" or "enp3s0"
     * @param string $inputInterfaceName
     * @return array[]
     */
    public static function createMatchInputInterfaceName(string $inputInterfaceName) : NftablesMatch
    {
        $left = [
            "meta" => [
                "key" => "iifname"
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::EQUALS, $left, $inputInterfaceName);
    }


    /**
     * Create a match rule for the name of an output interface. E.g. "lo" or "enp3s0"
     * @param string $outputInterfaceName
     * @return array[]
     */
    public static function createMatchOutputInterfaceName(string $outputInterfaceName) : NftablesMatch
    {
        $left = [
            "meta" => [
                "key" => "oifname"
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::EQUALS, $left, $outputInterfaceName);
    }


    /**
     * Create a match against a destination single IP address or a CIDR of multiple IP addresses.
     * @param string $ipOrCidr
     * @return \Programster\Nftables\NftablesMatch
     * @throws \Programster\Nftables\Exceptions\ExceptionInvalidNetworkCidr
     */
    public static function createMatchDestinationIpOrCidr(string $ipOrCidr) : NftablesMatch
    {
        $left = [
            "payload" => [
                "protocol" => "ip",
                "field" => "daddr"
            ]
        ];

        return self::createMatchIpOrCidr($left, $ipOrCidr);
    }


    /**
     * Create a match against a source single IP address or a CIDR of multiple IP addresses.
     * @param string $ipOrCidr - the IP address or network CIDR to match against.
     * @return NftablesMatch
     * @throws \Programster\Nftables\Exceptions\ExceptionInvalidNetworkCidr
     */
    public static function createMatchSourceIpOrCidr(string $ipOrCidr) : NftablesMatch
    {
        $left = [
            "payload" => [
                "protocol" => "ip",
                "field" => "saddr"
            ]
        ];

        return self::createMatchIpOrCidr($left, $ipOrCidr);
    }


    /**
     * Create a match against a list of allowed states. If the connection is in ANY of these states (e.g. OR),
     * then it is considered a match. This is useful for specifying that one wishes to allow through any
     * established/related connections.
     * @param NftablesConnectionState ...$allowedStates
     * @return array[]
     * @throws ExceptionConnectionStateRequired - if no connection states were passed
     */
    public static function createMatchConnectionStates(NftablesConnectionState ...$allowedStates) : NftablesMatch
    {
        if (count($allowedStates) === 0)
        {
            throw new ExceptionConnectionStateRequired();
        }

        $allowedStatesStrings = [];

        foreach ($allowedStates as $allowedState)
        {
            $allowedStatesStrings[] = $allowedState->value;
        }

        $allowedStatesStrings = array_unique($allowedStatesStrings);

        if (count($allowedStatesStrings) === 0)
        {
            throw new ExceptionConnectionStateRequired();
        }

        $left = [
            "ct" => [
                "key" => "state"
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::IN, $left, $allowedStatesStrings);
    }


    /**
     * Create a match statement for seeing if is a TCP syn packet.
     * UDP does not have Syn.
     * This is only good for allowing the forwarding of a SYN package for new connections
     * @return array[]
     */
    public static function createMatchTcpSynFlag() : NftablesMatch
    {
        $left = [
            "&" => [
                [
                    "payload" => [
                        "protocol" => "tcp",
                        "field" => "flags"
                    ]
                ],
                [
                    "fin",
                    "syn",
                    "rst",
                    "ack"
                ]
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::EQUALS, $left, "syn");
    }


    /**
     * Create a match against a source single IP address or a CIDR of multiple IP addresses.
     * @param array $left
     * @param string $ipOrCidr - the IP address or network CIDR to match against.
     * @return NftablesMatch
     * @throws \Programster\Nftables\Exceptions\ExceptionInvalidNetworkCidr
     */
    private static function createMatchIpOrCidr(array $left, string $ipOrCidr) : NftablesMatch
    {
        if (Factory::parseAddressString($ipOrCidr) !== null)
        {
            $result = new NftablesMatch(NftablesMatchOperator::EQUALS, $left, $ipOrCidr);
        }
        else if (Subnet::parseString($ipOrCidr) !== null)
        {
            $result = self::createMatchCidr($left, $ipOrCidr);
        }
        else
        {
            throw new \Exception("{$ipOrCidr} is not an IP address or CIDR.");
        }

        return $result;
    }


    private static function createMatchCidr(array $left, string $cidr) : NftablesMatch
    {
        if (NftablesLib::isValidNetworkCidr($cidr) === false)
        {
            if (NftablesLib::isValidNetworkCidr($cidr))
            {
                throw new ExceptionInvalidNetworkCidr("{$cidr} is a valid CIDR but not a valid *network* CIDR.");
            }
            else
            {
                throw new ExceptionInvalidNetworkCidr("{$cidr} is not a valid network CIDR.");
            }
        }

        $parts = explode("/", $cidr);
        $address = $parts[0];
        $prefixLength = $parts[1];

        $right = [
            "prefix" => [
                "addr" => $address,
                "len" => $prefixLength
            ]
        ];

        return new NftablesMatch(NftablesMatchOperator::IN, $left, $right);
    }
}