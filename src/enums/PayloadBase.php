<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Where a raw payload expression's offset is measured from.
 */
enum PayloadBase : string
{
    case LINK_LAYER = "ll";
    case NETWORK_LAYER = "nh";
    case TRANSPORT_LAYER = "th";
}
