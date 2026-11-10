<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\TableFlag;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A table, which holds chains and sets. Each table belongs to one address family, which decides which packets its
 * chains see.
 */
final readonly class Table
{
    private string $m_name;
    private Family $m_family;

    /** @var string[] - the flags' values, without duplicates. */
    private array $m_flags;


    /**
     * Create a table.
     *
     * @param string $name - the table's name. Pick a distinctive one (not e.g. "filter" or "nat"), so it can't clash
     * with a table that other software (e.g. iptables-nft, and so Docker) uses.
     *
     * @param Family $family - the table's address family.
     *
     * @param TableFlag ...$flags - the table's flags. TableFlag::DORMANT turns all of its rules off.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Family $family, TableFlag ...$flags)
    {
        NameLib::assertValidName($name, "table");
        $this->m_name = $name;
        $this->m_family = $family;
        $this->m_flags = array_values(array_unique(array_column($flags, "value")));
    }


    /**
     * Get the table in the form nftables expects.
     *
     * @return array
     */
    public function toArray() : array
    {
        $table = $this->toIdentifierArray();

        if (count($this->m_flags) > 0)
        {
            $table["table"]["flags"] = $this->m_flags;
        }

        return $table;
    }


    /**
     * Get just what identifies the table (its family and name), in the form nftables expects, e.g. for deleting it.
     *
     * @return array
     */
    public function toIdentifierArray() : array
    {
        return ["table" => ["family" => $this->m_family->value, "name" => $this->m_name]];
    }


    /**
     * Check whether another table is the same table in nftables, i.e. has the same family and name. Their flags aren't
     * compared.
     *
     * @param Table $other - the table to compare with.
     *
     * @return bool
     */
    public function isSameTableAs(Table $other) : bool
    {
        return $this->m_family === $other->getFamily() && $this->m_name === $other->getName();
    }


    # Accessors
    public function getName() : string { return $this->m_name; }
    public function getFamily() : Family { return $this->m_family; }
}
