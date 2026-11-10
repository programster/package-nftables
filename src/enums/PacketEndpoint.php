<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which end of a packet's journey something refers to: where it came from, or where it's going.
 */
enum PacketEndpoint
{
    case SOURCE;
    case DESTINATION;


    /**
     * Get the name of this end's port field, as nftables writes it in a transport header (e.g. "tcp dport").
     *
     * @return string - "sport" or "dport".
     */
    public function getPortField() : string
    {
        return match ($this) {
            PacketEndpoint::SOURCE => "sport",
            PacketEndpoint::DESTINATION => "dport",
        };
    }


    /**
     * Get the name of this end's address field, as nftables writes it in an IP header (e.g. "ip saddr").
     *
     * @return string - "saddr" or "daddr".
     */
    public function getAddressField() : string
    {
        return match ($this) {
            PacketEndpoint::SOURCE => "saddr",
            PacketEndpoint::DESTINATION => "daddr",
        };
    }
}
