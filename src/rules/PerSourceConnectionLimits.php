<?php

declare(strict_types=1);

namespace Programster\Nftables\Rules;

use Programster\Nftables\Collections\ConnectionRateLimitCollection;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\ConflictException;
use Programster\Nftables\Internal\NameLib;
use WeakMap;

/**
 * The limits on the connections each source address can make, for RuleFactory::createPerSourceConnectionLimits(): at
 * most $maxConnections open at once, and at most a number of new ones per period, for each of its rates (e.g. 60 a
 * minute, and 100 an hour). A connection that's accepted counts towards every one of them.
 *
 * Each source address is counted in named sets, which are named after the limits, so every rule given the same
 * PerSourceConnectionLimits object shares one count per address. E.g. pass the same object for a server's ports 465
 * and 587, and an address can have $maxConnections open across both ports, not that many on each. For a separate
 * count, create another object.
 *
 * Two objects can never have the same name at once, as they'd then share their sets, and so their counts, by accident.
 * Creating one with a name that another one still has throws a ConflictException.
 */
final class PerSourceConnectionLimits
{
    /**
     * The name of each object that still exists, so a name can't be given to a second one. An object's name is
     * forgotten once the object no longer exists, so it can be used again.
     *
     * @var WeakMap<PerSourceConnectionLimits, string>|null
     */
    private static ?WeakMap $s_namesInUse = null;

    private readonly string $m_name;
    private readonly ?int $m_maxConnections;

    // Sorted shortest period first.
    private readonly ConnectionRateLimitCollection $m_rates;

    private readonly int $m_maxSources;


    /**
     * Create the limits on the connections each source address can make. There has to be at least one: a maximum
     * open at once, or a rate.
     *
     * @param int|null $maxConnections - optionally, the most connections each source address can have open at once.
     * Defaults to null, for no limit.
     *
     * @param ConnectionRateLimitCollection $rates - the limits on how many new connections each source address can
     * open per period, at most one for each period (as only the lowest of two for the same period would ever apply).
     * They're checked shortest period first, whatever order they're given in, so a burst refused by a short period's
     * limit doesn't use up a longer one's. Defaults to none.
     *
     * @param string|null $name - optionally, a name for the limits, which their sets are named after:
     * "{$name}_per_<period>" for each rate (e.g. "{$name}_per_minute"), and "{$name}_connections" for the number open
     * at once, e.g. for looking inside them with "nft list set". It must be unique among the sets and maps in each
     * table the limits are used in. Defaults to null, which generates a unique name, "limits_" followed by a random
     * UUID. A generated name is different every time the code runs, so the ruleset's JSON is too, and it doesn't say
     * what the limits are for, so give one to make the sets easy to find.
     *
     * @param int $maxSources - the most source addresses each set tracks at once. Once they're full, new addresses'
     * connections are refused until old ones expire, so make it comfortably bigger than the number of clients.
     * Defaults to 65535.
     *
     * @throws BadArgumentException - if there are no limits, $maxConnections or $maxSources is less than 1, two rates
     * are for the same period, or the name is empty or too long.
     *
     * @throws ConflictException - if another PerSourceConnectionLimits object that still exists has the same name.
     */
    public function __construct(
        ?int $maxConnections = null,
        ConnectionRateLimitCollection $rates = new ConnectionRateLimitCollection(),
        ?string $name = null,
        int $maxSources = 65535,
    )
    {
        if ($maxConnections === null && count($rates) === 0)
        {
            $message = "Per-source connection limits need at least one limit: a maximum open at once, or a rate.";
            throw new BadArgumentException($message);
        }

        if (($maxConnections !== null && $maxConnections < 1) || $maxSources < 1)
        {
            $message = "Per-source connection limits need a maximum of at least 1 connection open at once, and 1"
                . " source address.";

            throw new BadArgumentException($message);
        }

        self::assertOneRatePerPeriod($rates);

        if ($name === null)
        {
            $this->m_name = "limits_" . self::generateUuid();
        }
        else
        {
            if ($name === "")
            {
                throw new BadArgumentException("Per-source connection limits can't have an empty name.");
            }

            // Its longest set name has to fit.
            NameLib::assertValidName("{$name}_connections", "set");
            self::assertNameNotInUse($name);
            $this->m_name = $name;
        }

        $this->m_maxConnections = $maxConnections;
        $this->m_rates = $rates->sort("getPeriodSeconds");
        $this->m_maxSources = $maxSources;
        self::getNamesInUse()[$this] = $this->m_name;
    }


    /**
     * Check that no two rates are for the same period.
     * @param ConnectionRateLimitCollection $rates - the rates.
     * @return void
     * @throws BadArgumentException - if two are.
     */
    private static function assertOneRatePerPeriod(ConnectionRateLimitCollection $rates) : void
    {
        $periodsSeen = [];

        foreach ($rates as $rate)
        {
            $period = $rate->getPeriod()->value;

            if (isset($periodsSeen[$period]))
            {
                $message = "Per-source connection limits can only have one rate per {$period}, as only the lowest of"
                    . " them would ever apply.";

                throw new BadArgumentException($message);
            }

            $periodsSeen[$period] = true;
        }
    }


    /**
     * Check that no other PerSourceConnectionLimits object that still exists has a name.
     * @param string $name - the name.
     * @return void
     * @throws ConflictException - if one does.
     */
    private static function assertNameNotInUse(string $name) : void
    {
        foreach (self::getNamesInUse() as $nameInUse)
        {
            if ($nameInUse === $name)
            {
                $message = "Other per-source connection limits are already named \"{$name}\". To share their limits,"
                    . " and their count of each address's connections, pass that same object. Otherwise, give these"
                    . " another name.";

                throw new ConflictException($message);
            }
        }
    }


    /**
     * Get the names of the PerSourceConnectionLimits objects that still exist, creating the map the first time.
     * @return WeakMap<PerSourceConnectionLimits, string>
     */
    private static function getNamesInUse() : WeakMap
    {
        if (self::$s_namesInUse === null)
        {
            self::$s_namesInUse = new WeakMap();
        }

        return self::$s_namesInUse;
    }


    /**
     * Generate a random (version 4) UUID, e.g. "3f2b8c1e-9a4d-4e7b-b6f0-2d5c8e1a7f93".
     * @return string
     */
    private static function generateUuid() : string
    {
        $bytes = random_bytes(16);

        // Set the version (4) and the variant (RFC 9562).
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf("%s%s-%s-%s-%s-%s%s%s", str_split(bin2hex($bytes), 4));
    }


    # Accessors
    public function getName() : string { return $this->m_name; }
    public function getMaxConnections() : ?int { return $this->m_maxConnections; }
    public function getRates() : ConnectionRateLimitCollection { return $this->m_rates; }
    public function getMaxSources() : int { return $this->m_maxSources; }
}
