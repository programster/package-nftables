<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A piece of connection tracking data, for a CtExpression.
 */
enum CtKey : string
{
    case STATE = "state";
    case DIRECTION = "direction";
    case STATUS = "status";
    case MARK = "mark";
    case EXPIRATION = "expiration";
    case HELPER = "helper";
    case LABEL = "label";
    case L3PROTO = "l3proto";
    case PROTOCOL = "protocol";

    // Needs a direction and an IP version.
    case SADDR = "saddr";

    // Needs a direction and an IP version.
    case DADDR = "daddr";

    // Needs a direction.
    case PROTO_SRC = "proto-src";

    // Needs a direction.
    case PROTO_DST = "proto-dst";
    case BYTES = "bytes";
    case PACKETS = "packets";
    case AVGPKT = "avgpkt";
    case ZONE = "zone";
    case ID = "id";
}
