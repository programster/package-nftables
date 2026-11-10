<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A transport protocol that has ports.
 */
enum Protocol : string
{
    case TCP = "tcp";
    case UDP = "udp";
    case UDPLITE = "udplite";
    case SCTP = "sctp";
    case DCCP = "dccp";
}
