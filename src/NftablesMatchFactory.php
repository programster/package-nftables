<?php

/*
 * A library for creating matches for rules
 */

namespace Programster\Nftables;


use Programster\Nftables\Enums\NftablesConnectionState;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Exceptions\ExceptionConnectionStateRequired;
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
    public static function createMatchDestinationPorts(Protocol $protocol, int ...$ports) : array
    {
        $ports = array_unique($ports);

        if (count($ports) === 0)
        {
            throw new ExceptionPortRequired();
        }

        if (count($ports) === 1)
        {
            $match = [
                "match" => [
                    "op" => "==",
                    "left" => [
                        "payload" => [
                            "protocol" => $protocol->value,
                            "field" => "dport"
                        ]
                    ],
                    "right" => array_pop($ports)
                ]
            ];
        }
        else
        {
            $match = [
                "match" => [
                    "op" => "==",
                    "left" => [
                        "payload" => [
                            "protocol" => $protocol->value,
                            "field" => "dport"
                        ]
                    ],
                    "right" => [
                        "set" => $ports
                    ]
                ]
            ];
        }

        return $match;
    }


    /**
     * Create a match against a port range. E.g. 5000-6000
     * @param Protocol $protocol - the type of traffic (TCP/UDP)
     * @param PortRange $portRange - the range of ports to match against.
     * @return array[]
     */
    public static function createMatchDestinationPortRange(Protocol $protocol, PortRange $portRange) : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
                    "payload" => [
                        "protocol" => $protocol->value,
                        "field" => "dport"
                    ]
                ],
                "right" => [
                    "range" => [
                        $portRange->minPort,
                        $portRange->maxPort,
                    ]
                ]
            ]
        ];
    }


    /**
     * Create a match rule for the name of an input interface. E.g. "lo" or "enp3s0"
     * @param string $inputInterfaceName
     * @return array[]
     */
    public static function createMatchInputInterfaceName(string $inputInterfaceName) : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
                    "meta" => [
                        "key" => "iifname"
                    ]
                ],
                "right" => $inputInterfaceName
            ]
        ];
    }


    /**
     * Create a match rule for the name of an output interface. E.g. "lo" or "enp3s0"
     * @param string $outputInterfaceName
     * @return array[]
     */
    public static function createMatchOutputInterfaceName(string $outputInterfaceName) : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
                    "meta" => [
                        "key" => "oifname"
                    ]
                ],
                "right" => $outputInterfaceName
            ]
        ];
    }


    /**
     * Create a match against a destination single IP address or a CIDR of multiple IP addresses.
     * @param string $ipAddress
     * @return array[]
     */
    public static function createMatchDestinationIpOrCidr(string $ipAddress) : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
                    "payload" => [
                        "protocol" => "ip",
                        "field" => "daddr"
                    ]
                ],
                "right" => $ipAddress
            ]
        ];
    }


    /**
     * Create a match against a source single IP address or a CIDR of multiple IP addresses.
     * @param string $ipAddress
     * @return array[]
     */
    public static function createMatchSourceIpOrCidr(string $ipAddress) : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
                    "payload" => [
                        "protocol" => "ip",
                        "field" => "saddr"
                    ]
                ],
                "right" => $ipAddress
            ]
        ];
    }


    /**
     * Create a match against a list of allowed states. If the connection is in ANY of these states (e.g. OR),
     * then it is considered a match. This is useful for specifying that one wishes to allow through any
     * established/related connections.
     * @param NftablesConnectionState ...$allowedStates
     * @return array[]
     * @throws ExceptionConnectionStateRequired - if no connection states were passed
     */
    public static function createMatchConnectionStates(NftablesConnectionState ...$allowedStates) : array
    {
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

        return [
            "match" => [
                "op" => "in",
                "left" => [
                    "ct" => [
                        "key" => "state"
                    ]
                ],
                "right" => $allowedStatesStrings
            ]
        ];
    }


    /**
     * Create a match statement for seeing if is a TCP syn packet.
     * UDP does not have Syn.
     * This is only good for allowing the forwarding of a SYN package for new connections
     * @return array[]
     */
    public static function createMatchTcpSynFlag() : array
    {
        return [
            "match" => [
                "op" => "==",
                "left" => [
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
                ],
                "right" => "syn"
            ]
        ];
    }
}