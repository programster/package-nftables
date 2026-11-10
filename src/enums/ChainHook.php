<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The point in the network stack where a base chain sees packets.
 */
enum ChainHook : string
{
    // Every incoming packet, before routing decides where it's going.
    case PREROUTING = "prerouting";

    // Incoming packets addressed to this machine.
    case INPUT = "input";

    // Packets passing through this machine, to somewhere else.
    case FORWARD = "forward";

    // Packets sent by processes on this machine.
    case OUTPUT = "output";

    // Every outgoing packet, after routing, just before it leaves.
    case POSTROUTING = "postrouting";

    // Packets as they arrive at a network device (netdev, or inet with a device).
    case INGRESS = "ingress";

    // Packets as they leave a network device (netdev only).
    case EGRESS = "egress";
}
