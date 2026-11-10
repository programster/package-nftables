<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which direction of a tracked connection a CtExpression reads.
 */
enum CtDirection : string
{
    // The direction of the packet that started the connection.
    case ORIGINAL = "original";

    // The other direction.
    case REPLY = "reply";
}
