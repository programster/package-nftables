<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The ICMP (IPv4) error a RejectStatement replies with. ip and inet tables only.
 */
enum IcmpRejectCode : string
{
    case NET_UNREACHABLE = "net-unreachable";
    case HOST_UNREACHABLE = "host-unreachable";
    case PROT_UNREACHABLE = "prot-unreachable";
    case PORT_UNREACHABLE = "port-unreachable";
    case NET_PROHIBITED = "net-prohibited";
    case HOST_PROHIBITED = "host-prohibited";
    case ADMIN_PROHIBITED = "admin-prohibited";
}
