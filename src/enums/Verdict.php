<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

use Programster\Nftables\Statements\Statement;

/**
 * A verdict that ends a rule's processing of a packet. Jumping to, or going to, another chain is done with
 * JumpStatement and GotoStatement, as they need a target.
 */
enum Verdict : string implements Statement
{
    // Accept the packet, and stop evaluating this base chain.
    case ACCEPT = "accept";

    // Drop the packet, and stop evaluating everything.
    case DROP = "drop";

    // Carry on with the next rule.
    case CONTINUE = "continue";

    // Return to the chain that jumped here, or apply the policy in a base chain.
    case RETURN = "return";

    /**
     * Get the verdict as a statement, in the form nftables expects.
     *
     * @return array
     */
    public function toArray() : array
    {
        return [$this->value => null];
    }
}
