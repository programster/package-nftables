<?php

namespace Programster\Nftables\Enums;

// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

enum NftablesVerdict: string
{
    case ACCEPT = "accept"; // Accept the packet and stop the remain rules evaluation.
    case DROP = "drop"; // Drop the packet and stop the remain rules evaluation.
    case QUEUE = "queue"; // Queue the packet to userspace and stop the remain rules evaluation.
    case CONTINUE = "continue"; // Continue the ruleset evaluation with the next rule.
    case RETURN = "return"; // Return from the current chain and continue at the next rule of the last chain. In a base chain it is equivalent to accept
    case JUMP = "jump"; // Continue at the first rule of <chain>. It will continue at the next rule after a return statement is issued
    case GO_TO = "goto"; // Similar to jump, but after the new chain the evaluation will continue at the last chain instead of the one containing the goto statement
}
