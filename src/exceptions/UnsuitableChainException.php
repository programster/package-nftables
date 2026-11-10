<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

/**
 * Thrown when a chain can't be used for something, e.g. a NAT rule given a filter chain, or a jump to a chain in a
 * different table.
 */
class UnsuitableChainException extends BadArgumentException
{
}
