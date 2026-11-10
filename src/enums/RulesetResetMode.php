<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a Ruleset clears out before loading its own tables. Whichever is chosen, the clear out happens in
 * the same nft transaction as the load, so if anything fails to load, nothing is changed.
 */
enum RulesetResetMode
{
    // Delete and recreate only the tables this ruleset defines. Tables created by anything else on the
    // machine (e.g. fail2ban or Docker) are left alone.
    case REPLACE_OWN_TABLES;

    // Flush the machine's entire ruleset, including tables this ruleset knows nothing about.
    case FLUSH_ENTIRE_RULESET;
}
