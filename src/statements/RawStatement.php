<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

/**
 * A statement given directly in nftables' JSON form, for anything this package doesn't model yet (e.g. a quota, or a
 * verdict map). It's passed to nftables exactly as given, without any checks, so double check it against the
 * libnftables-json documentation.
 */
final readonly class RawStatement implements Statement
{
    private array $m_statement;


    /**
     * Create a raw statement.
     *
     * @param array $statement - the statement, exactly as nftables' JSON expects it, e.g.
     * ["quota" => ["val" => 25, "val_unit" => "mbytes"]].
     */
    public function __construct(array $statement)
    {
        $this->m_statement = $statement;
    }


    public function toArray() : array
    {
        return $this->m_statement;
    }
}
