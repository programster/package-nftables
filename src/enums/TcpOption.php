<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A TCP option, for a TcpOptionExpression.
 */
enum TcpOption : string
{
    // The maximum segment size (MSS).
    case MAXSEG = "maxseg";

    // Window scaling.
    case WINDOW = "window";

    // Selective acknowledgements are allowed.
    case SACK_PERMITTED = "sack-perm";

    // A selective acknowledgement. Its blocks (sack0 to sack3) are fields: see TcpOptionField.
    case SACK = "sack";
    case TIMESTAMP = "timestamp";
}
