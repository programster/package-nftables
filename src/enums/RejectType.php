<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The kind of reply a RejectStatement sends. RejectStatement's creators pick it, so this rarely needs using directly.
 */
enum RejectType : string
{
    // nftables' default reply, an ICMP port unreachable error.
    case DEFAULT = "";

    case TCP_RESET = "tcp reset";
    case ICMPX = "icmpx";
    case ICMP = "icmp";
    case ICMPV6 = "icmpv6";
}
