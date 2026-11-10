<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a SetUpdateStatement does to a named set.
 */
enum SetUpdateOperation : string
{
    // Add the element, unless it's already there. An element that's already there keeps its expiry time.
    case ADD = "add";

    // Add the element, or if it's already there, restart its expiry time.
    case UPDATE = "update";

    // Remove the element, if it's there.
    case DELETE = "delete";
}
