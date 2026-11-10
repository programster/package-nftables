<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

use LogicException;

/**
 * Thrown when a ruleset is given something its target's nft (or kernel) can't load, or would silently ignore. Give the
 * Ruleset a newer NftablesTarget to use it.
 */
class UnsupportedFeatureException extends LogicException implements NftablesException
{
}
