<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

use Throwable;

/**
 * Every exception this package throws implements this, so they can all be caught together.
 */
interface NftablesException extends Throwable
{
}
