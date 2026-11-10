<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

use InvalidArgumentException;

/**
 * Thrown when an argument can't be valid nftables, e.g. a port above 65535, or a log prefix that's too long.
 */
class BadArgumentException extends InvalidArgumentException implements NftablesException
{
}
