<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a SocketExpression reads from the local socket a packet belongs to.
 */
enum SocketKey : string
{
    // 1 if the socket has IP_TRANSPARENT set, e.g. a transparent proxy's.
    case TRANSPARENT = "transparent";

    // The socket's mark (SO_MARK). Needs kernel 4.19.
    case MARK = "mark";

    // 1 if the socket is listening on a wildcard address (e.g. 0.0.0.0). Needs kernel 5.6.
    case WILDCARD = "wildcard";
}
