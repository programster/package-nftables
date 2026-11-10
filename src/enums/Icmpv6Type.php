<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * An ICMPv6 message type, using the names nftables uses for them, for MatchFactory::createIcmpv6Types(). Every nft
 * version from 0.9.8 has the same names.
 */
enum Icmpv6Type : string
{
    // Errors, sent back about a packet that couldn't be delivered.
    case DESTINATION_UNREACHABLE = "destination-unreachable";
    case PACKET_TOO_BIG = "packet-too-big";
    case TIME_EXCEEDED = "time-exceeded";
    case PARAMETER_PROBLEM = "parameter-problem";

    // Ping.
    case ECHO_REQUEST = "echo-request";
    case ECHO_REPLY = "echo-reply";

    // Multicast listener discovery, which tells the network's switches and routers which multicast groups (including
    // the ones neighbour discovery uses) a machine is listening to.
    case MLD_LISTENER_QUERY = "mld-listener-query";
    case MLD_LISTENER_REPORT = "mld-listener-report";
    case MLD_LISTENER_DONE = "mld-listener-done";
    case MLD2_LISTENER_REPORT = "mld2-listener-report";

    // Neighbour discovery, which IPv6 uses in place of ARP, and to find routers and configure addresses.
    case ND_ROUTER_SOLICIT = "nd-router-solicit";
    case ND_ROUTER_ADVERT = "nd-router-advert";
    case ND_NEIGHBOR_SOLICIT = "nd-neighbor-solicit";
    case ND_NEIGHBOR_ADVERT = "nd-neighbor-advert";
    case ND_REDIRECT = "nd-redirect";
    case ROUTER_RENUMBERING = "router-renumbering";
    case IND_NEIGHBOR_SOLICIT = "ind-neighbor-solicit";
    case IND_NEIGHBOR_ADVERT = "ind-neighbor-advert";
}
