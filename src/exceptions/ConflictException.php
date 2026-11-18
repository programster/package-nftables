<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

use LogicException;

/**
 * Thrown when a Ruleset is given two different tables, chains or sets with the same name in the same place, or a
 * PerSourceConnectionLimits is given a name that other limits already have.
 */
class ConflictException extends LogicException implements NftablesException
{
}
