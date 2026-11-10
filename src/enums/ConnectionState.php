<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A connection tracking state, for matching with ct state.
 */
enum ConnectionState : string
{
    // The first packet of a new connection.
    case NEW = "new";

    // Part of a connection that has seen packets in both directions.
    case ESTABLISHED = "established";

    // Starts a connection related to an existing one (e.g. an FTP data connection, or an ICMP error).
    case RELATED = "related";

    // Doesn't belong to any known connection. Usually worth dropping.
    case INVALID = "invalid";

    // Exempted from connection tracking (see NotrackStatement).
    case UNTRACKED = "untracked";
}
