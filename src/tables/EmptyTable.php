<?php

declare(strict_types=1);

namespace Programster\Nftables\Tables;

use Programster\Nftables\Enums\Family;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A table with nothing in it, for a Ruleset that should include one, e.g. to empty a table that's no longer used,
 * without deleting it. With RulesetResetMode::REPLACE_OWN_TABLES, loading the ruleset deletes it and recreates it
 * empty, every time.
 *
 * It isn't a Table, so nothing can be created in it. A table with anything in it doesn't need this, as its chains,
 * sets and other items bring it into the ruleset. A Ruleset refuses an empty table with the same family and name as
 * one that's in use.
 */
final readonly class EmptyTable
{
    // Only to check the arguments as a table's are checked, and never handed out, so nothing can be put in it.
    private Table $m_table;


    /**
     * Create an empty table.
     *
     * @param string $name - the table's name.
     *
     * @param Family $family - the table's address family. Tables in different families are separate, even with the
     * same name.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Family $family)
    {
        $this->m_table = new Table($name, $family);
    }


    # Accessors
    public function getName() : string { return $this->m_table->getName(); }
    public function getFamily() : Family { return $this->m_table->getFamily(); }
}
