<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

use LogicException;

/**
 * Thrown when a Ruleset is given two different tables, chains or sets with the same name in the same place.
 */
class ConflictException extends LogicException implements NftablesException
{
}
