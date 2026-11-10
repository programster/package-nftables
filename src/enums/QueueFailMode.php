<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What happens to queued packets when no program is reading the queue.
 */
enum QueueFailMode
{
    // Drop them. Nothing gets through while the program isn't running.
    case DROP;

    // Accept them, as if they hadn't been queued. Traffic flows unchecked while the program isn't running.
    case ACCEPT;
}
