<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Rule;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of rules, in the order they're evaluated. Anything that isn't a Rule is rejected as it's added.
 *
 * @extends AbstractCollection<Rule>
 */
final class RuleCollection extends AbstractCollection
{
    public function getType() : string
    {
        return Rule::class;
    }
}
