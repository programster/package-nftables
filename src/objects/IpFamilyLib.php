<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Enums\Family;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Table;

/**
 * Checks the tables of the objects that only exist for IP traffic.
 *
 * @internal
 */
final class IpFamilyLib
{
    private function __construct()
    {
    }


    /**
     * Check that a table is an ip, ip6 or inet table.
     *
     * @param Table $table - the table.
     *
     * @param string $what - what needs it, for the message, e.g. "A ct helper".
     *
     * @return void
     *
     * @throws BadArgumentException - if it isn't.
     */
    public static function assertIpFamily(Table $table, string $what) : void
    {
        $family = $table->getFamily();

        if (!in_array($family, [Family::IP, Family::IP6, Family::INET], true))
        {
            throw new BadArgumentException("{$what} needs an ip, ip6 or inet table, not {$family->value}.");
        }
    }
}
