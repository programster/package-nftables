<?php

namespace Programster\Nftables;


readonly class NftablesLib
{
   /**
     * Create the section for specifying the DNAT or the destination ip and port for a prerouting/forwarding rule.
     * @param string $desiredIp
     * @param int $desiredPort
     * @return array[]
     */
    public static function createDnat(string $desiredIp, int $desiredPort) : array
    {
        return [
            "dnat" => [
                "addr" => $desiredIp,
                "port" => $desiredPort
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