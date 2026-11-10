<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Checks the names of tables, chains and sets.
 *
 * @internal
 */
final class NameLib
{
    // The kernel's limit, which includes a terminating null byte.
    private const MAX_NAME_BYTES = 255;


    private function __construct()
    {
    }


    /**
     * Check that a name can be used for a table, chain or set.
     *
     * @param string $name - the name.
     *
     * @param string $what - what it names, for the message, e.g. "table".
     *
     * @return void
     *
     * @throws BadArgumentException - if it's empty or too long.
     */
    public static function assertValidName(string $name, string $what) : void
    {
        if ($name === "" || strlen($name) > self::MAX_NAME_BYTES)
        {
            throw new BadArgumentException("A {$what} name must be from 1 to " . self::MAX_NAME_BYTES . " bytes long.");
        }
    }
}
