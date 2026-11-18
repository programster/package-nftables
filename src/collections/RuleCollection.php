<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Rules\Rule;

/**
 * A list of rules, in the order they're evaluated, e.g. for a Ruleset. It can't be changed once it's created, so it can
 * be shared freely.
 *
 * @extends AbstractReadonlyCollection<Rule>
 */
final readonly class RuleCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of rules, in the order they're evaluated.
     * @param Rule ...$rules - the rules, in the order they're evaluated. There can be none.
     */
    public function __construct(Rule ...$rules)
    {
        parent::__construct(...$rules);
    }
}
