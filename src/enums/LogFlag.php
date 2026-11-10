<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Extra information a LogStatement adds to each entry.
 */
enum LogFlag : string
{
    case TCP_SEQUENCE = "tcp sequence";
    case TCP_OPTIONS = "tcp options";
    case IP_OPTIONS = "ip options";

    // The user ID of the socket that sent it.
    case SKUID = "skuid";

    // The link layer header.
    case ETHER = "ether";

    // Everything above.
    case ALL = "all";
}
