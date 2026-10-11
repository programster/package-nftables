<?php

namespace Programster\Nftables;


use IPLib\Factory;
use IPLib\Range\Subnet;

readonly class NftablesLib
{
    /**
     * Create the section for specifying the DNAT or the destination ip and port/port-range for a prerouting/forwarding rule.
     * @param string $desiredIp
     * @param int|PortRange $desiredPort - the desired port or range of ports.
     * @return array[]
     */
    public static function createDnat(string $desiredIp, int|PortRange $desiredPort) : array
    {
        if ($desiredPort instanceof PortRange)
        {
            $desiredPortBlock = [
                "range" => [
                    $desiredPort->minPort,
                    $desiredPort->maxPort,
                ]
            ];
        }
        else
        {
            $desiredPortBlock = $desiredPort;
        }

        return [
            "dnat" => [
                "addr" => $desiredIp,
                "port" => $desiredPortBlock
            ]
        ];
    }


    public static function createMetaInfoBlock() : array
    {
        return [
            "metainfo" => [
                "version"=> "1.0.6",
                "release_name"=> "Lester Gooch #5",
                "json_schema_version"=> 1,
            ],
        ];
    }


    /**
     * Check that the provided string is a valid CIDR such as 192.168.1.6/24.
     * Be sure to use isValidNetworkCidr() instead if you want a network CIDR.
     * @param string $cidr
     * @return bool
     */
    public static function isValidCidr(string $cidr): bool
    {
        return Subnet::parseString($cidr) !== null;
    }


    /**
     * Check if the provided address was a valid network CIDR. e.g. something
     * like 192.168.0.0/24 and not 192.168.0.1/24. If you just want to check
     * that it is a valid CIDR, then use isValidCidr() instead.
     * @param string $cidr
     * @return bool - true if the provided string is a valid network cidr.
     */
    public static function isValidNetworkCidr(string $cidr) : bool
    {
        $result = false;
        $subnet = Subnet::parseString($cidr);

        if ($subnet !== null)
        {
            $suppliedAddress = explode('/', $cidr)[0];
            $address = Factory::parseAddressString($suppliedAddress);

            $result = (
                   $address !== null
                && $subnet->getStartAddress()->getComparableString() === $address->getComparableString()
            );
        }

        return $result;
    }
}
