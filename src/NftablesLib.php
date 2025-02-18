<?php

namespace Programster\Nftables;


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
}
