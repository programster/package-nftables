<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A named base chain priority. Chains on the same hook run in order of priority, lowest first. A chain can also be
 * given any integer instead, e.g. Priority::FILTER->getValue(Family::INET) + 10, to run just after the filter chains.
 *
 * The bridge family has its own set of names (DSTNAT, FILTER, OUT and SRCNAT), with different values, and the arp and
 * netdev families only have FILTER.
 */
enum Priority : string
{
    case RAW = "raw";
    case MANGLE = "mangle";
    case DSTNAT = "dstnat";
    case FILTER = "filter";
    case SECURITY = "security";
    case SRCNAT = "srcnat";

    // Bridge family only.
    case OUT = "out";


    /**
     * Get the number this priority stands for in a family, e.g. to give a chain a priority relative to it.
     *
     * @param Family $family - the family of the chain's table.
     *
     * @return int
     *
     * @throws BadArgumentException - if the priority has no meaning in that family (e.g. RAW in a bridge table).
     */
    public function getValue(Family $family) : int
    {
        $bridge = ["dstnat" => -300, "filter" => -200, "out" => 100, "srcnat" => 300];
        $ip = ["raw" => -300, "mangle" => -150, "dstnat" => -100, "filter" => 0, "security" => 50, "srcnat" => 100];

        $values = match ($family) {
            Family::BRIDGE => $bridge,
            Family::ARP, Family::NETDEV => ["filter" => 0],
            default => $ip,
        };

        if (!isset($values[$this->value]))
        {
            throw new BadArgumentException("The {$this->name} priority doesn't exist in the {$family->value} family.");
        }

        return $values[$this->value];
    }
}
