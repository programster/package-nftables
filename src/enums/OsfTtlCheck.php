<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * How an OsfExpression compares a packet's IP time to live with the fingerprints'.
 */
enum OsfTtlCheck
{
    // The TTL must match the fingerprint's exactly, which only works for machines on the same network.
    case EXACT;

    // The TTL can be lower than the fingerprint's, as it is once a packet has passed through routers.
    case LOOSE;

    // The TTL isn't checked.
    case SKIP;
}
