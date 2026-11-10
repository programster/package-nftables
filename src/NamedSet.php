<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\SetFlagCollection;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\SetFlag;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\Expressions\PrefixExpression;
use Programster\Nftables\Expressions\SetReference;

/**
 * A named set of values (e.g. addresses to block), which rules match against with getReference(). Unlike an anonymous
 * SetExpression, it can be shared by several rules, and its elements can be changed at runtime with "nft add element"
 * without reloading the rules.
 *
 * Rules can also add elements to it as packets arrive (see SetUpdateStatement), e.g. to block an address that opens too
 * many connections, which is what nft's meters do.
 *
 * Reloading a Ruleset recreates its sets with only the elements given here, so elements added at runtime are lost.
 */
final readonly class NamedSet implements TableItem
{
    private Table $m_table;
    private string $m_name;

    // More than one for a set of concatenations.
    private SetTypeCollection $m_types;

    // Without duplicates.
    private SetFlagCollection $m_flags;

    private int $m_timeoutSeconds;
    private int $m_maxElements;

    /** @var array<Expression|string|int> */
    private array $m_elements;


    /**
     * Create a named set. Use create() (or createAddressSet() or createPortSet()), withElements() and withTimeout().
     *
     * @param Table $table - the table the set belongs to.
     *
     * @param string $name - the set's name.
     *
     * @param SetTypeCollection $types - the type of the elements, or several for a set of concatenations.
     *
     * @param SetFlagCollection $flags - the set's flags.
     *
     * @param int $timeoutSeconds - how long elements last before they expire, or 0 for forever.
     *
     * @param int $maxElements - the most elements it can hold, or 0 for no limit.
     *
     * @param Expression|string|int ...$elements - the initial elements.
     *
     * @throws BadArgumentException - if the type, flags, size or elements aren't valid, or don't go together.
     */
    private function __construct(
        Table $table,
        string $name,
        SetTypeCollection $types,
        SetFlagCollection $flags,
        int $timeoutSeconds,
        int $maxElements,
        Expression|string|int ...$elements,
    )
    {
        NameLib::assertValidName($name, "set");
        $uniqueFlags = [];

        foreach ($flags as $flag)
        {
            $uniqueFlags[$flag->value] = $flag;
        }

        if (count($types) === 0)
        {
            throw new BadArgumentException("A set needs a type.");
        }

        if (!isset($uniqueFlags[SetFlag::INTERVAL->value]) && ExpressionLib::isAnyInterval(...$elements))
        {
            throw new BadArgumentException("A set needs the INTERVAL flag to hold ranges or prefixes.");
        }

        if ($timeoutSeconds < 0 || $maxElements < 0)
        {
            throw new BadArgumentException("A set's timeout and size can't be negative.");
        }

        if ($maxElements > 0 && count($elements) > $maxElements)
        {
            throw new BadArgumentException("A set can't be given more elements than its size.");
        }

        // Converted here only to check them, so a bad element is caught where it's added.
        ExpressionLib::toJsonList(...$elements);
        $this->m_table = $table;
        $this->m_name = $name;
        // Copies, as collections can be changed, and the caller still has these ones.
        $this->m_types = new SetTypeCollection($types->toArray());
        $this->m_flags = new SetFlagCollection(array_values($uniqueFlags));
        $this->m_timeoutSeconds = $timeoutSeconds;
        $this->m_maxElements = $maxElements;
        $this->m_elements = array_values($elements);
    }


    /**
     * Create an empty named set. Add its initial elements with withElements().
     *
     * @param Table $table - the table the set belongs to. Only rules in the same table can use it.
     *
     * @param string $name - the set's name, which must be unique within its table.
     *
     * @param SetType|SetTypeCollection $type - the type of the elements, or a collection of types for elements that
     * are a concatenation of values (e.g. an address and a port, as ConcatExpressions).
     *
     * @param SetFlag ...$flags - the set's flags. INTERVAL is needed for elements that are ranges or prefixes.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if there's no type, or the name is empty or too long.
     */
    public static function create(
        Table $table,
        string $name,
        SetType|SetTypeCollection $type,
        SetFlag ...$flags,
    ) : NamedSet
    {
        $types = ($type instanceof SetTypeCollection) ? $type : new SetTypeCollection([$type]);
        return new NamedSet($table, $name, $types, new SetFlagCollection($flags), 0, 0);
    }


    /**
     * Create a set of IP addresses and networks, e.g. for an allowlist or a blocklist. It always has the INTERVAL flag,
     * so networks can be added to it at runtime too.
     *
     * @param Table $table - the table the set belongs to.
     *
     * @param string $name - the set's name.
     *
     * @param IpVersion $ipVersion - whether it holds IPv4 or IPv6 addresses.
     *
     * @param string ...$addressesOrCidrs - the initial addresses (e.g. 10.0.0.1) and network CIDRs (e.g. 10.0.0.0/8).
     *
     * @return NamedSet
     *
     * @throws InvalidAddressException - if one isn't an address or network CIDR of that IP version.
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public static function createAddressSet(
        Table $table,
        string $name,
        IpVersion $ipVersion,
        string ...$addressesOrCidrs,
    ) : NamedSet
    {
        $elements = [];

        foreach ($addressesOrCidrs as $addressOrCidr)
        {
            if (NetworkLib::getIpVersion($addressOrCidr) !== $ipVersion)
            {
                throw new InvalidAddressException("{$addressOrCidr} isn't an {$ipVersion->name} address.");
            }

            $elements[] = str_contains($addressOrCidr, "/")
                ? PrefixExpression::createFromCidr($addressOrCidr)
                : $addressOrCidr;
        }

        $type = ($ipVersion === IpVersion::IPV4) ? SetType::IPV4_ADDR : SetType::IPV6_ADDR;
        return NamedSet::create($table, $name, $type, SetFlag::INTERVAL)->withElements(...$elements);
    }


    /**
     * Create a set of ports and port ranges. It always has the INTERVAL flag, so ranges can be added to it at runtime
     * too.
     *
     * @param Table $table - the table the set belongs to.
     *
     * @param string $name - the set's name.
     *
     * @param int|PortRange ...$ports - the initial ports and port ranges.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535, or the name is empty or too long.
     */
    public static function createPortSet(Table $table, string $name, int|PortRange ...$ports) : NamedSet
    {
        foreach ($ports as $port)
        {
            if (is_int($port))
            {
                NetworkLib::assertValidPort($port);
            }
        }

        return NamedSet::create($table, $name, SetType::INET_SERVICE, SetFlag::INTERVAL)->withElements(...$ports);
    }


    /**
     * Get a copy of the set with these initial elements, in place of any it had.
     *
     * @param Expression|string|int ...$elements - the elements, e.g. addresses, or PrefixExpressions for networks.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if an element is a range or prefix and the set doesn't have the INTERVAL flag, a
     * plain string starts with "@", or there are more elements than the set's size.
     */
    public function withElements(Expression|string|int ...$elements) : NamedSet
    {
        return $this->copy($this->m_flags, $this->m_timeoutSeconds, $this->m_maxElements, ...$elements);
    }


    /**
     * Get a copy of the set whose elements expire after a time. It's given the TIMEOUT flag, which nft needs for this.
     *
     * @param int $seconds - how long elements last, or 0 for forever.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if the time is negative.
     */
    public function withTimeout(int $seconds) : NamedSet
    {
        $flags = new SetFlagCollection([...$this->m_flags->toArray(), SetFlag::TIMEOUT]);
        return $this->copy($flags, $seconds, $this->m_maxElements, ...$this->m_elements);
    }


    /**
     * Get a copy of the set that can hold at most a number of elements. A set that rules add to (see
     * SetUpdateStatement) needs one, so traffic (e.g. from spoofed addresses) can't fill memory with elements, and a
     * timeout too. Once it's full, nothing more is added until elements expire or are deleted, and the rule adding them
     * stops there.
     *
     * @param int $maxElements - the most elements it can hold.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if it's less than 1, or less than the number of elements the set already has.
     */
    public function withSize(int $maxElements) : NamedSet
    {
        if ($maxElements < 1)
        {
            throw new BadArgumentException("A set's size must be at least 1.");
        }

        return $this->copy($this->m_flags, $this->m_timeoutSeconds, $maxElements, ...$this->m_elements);
    }


    /**
     * Get a reference to the set, for matching against it, e.g. in MatchFactory::createInSet().
     *
     * @return SetReference
     */
    public function getReference() : SetReference
    {
        return new SetReference($this);
    }


    public function toArray() : array
    {
        $typeValues = $this->m_types->column("value");

        $set = [
            "family" => $this->m_table->getFamily()->value,
            "table" => $this->m_table->getName(),
            "name" => $this->m_name,
            "type" => (count($typeValues) === 1) ? $typeValues[0] : $typeValues,
        ];

        if (count($this->m_flags) > 0)
        {
            $set["flags"] = $this->m_flags->column("value");
        }

        if ($this->m_timeoutSeconds > 0)
        {
            $set["timeout"] = $this->m_timeoutSeconds;
        }

        if ($this->m_maxElements > 0)
        {
            $set["size"] = $this->m_maxElements;
        }

        if (count($this->m_elements) > 0)
        {
            $set["elem"] = ExpressionLib::toJsonList(...$this->m_elements);
        }

        return ["set" => $set];
    }


    /**
     * Get a copy of the set with its type and name, and these flags, timeout, size and elements.
     *
     * @param SetFlagCollection $flags - the flags.
     *
     * @param int $timeoutSeconds - how long elements last, or 0 for forever.
     *
     * @param int $maxElements - the most elements it can hold, or 0 for no limit.
     *
     * @param Expression|string|int ...$elements - the elements.
     *
     * @return NamedSet
     *
     * @throws BadArgumentException - if they aren't valid, or don't go together.
     */
    private function copy(
        SetFlagCollection $flags,
        int $timeoutSeconds,
        int $maxElements,
        Expression|string|int ...$elements,
    ) : NamedSet
    {
        $table = $this->m_table;
        return new NamedSet($table, $this->m_name, $this->m_types, $flags, $timeoutSeconds, $maxElements, ...$elements);
    }


    # Accessors
    public function getTable() : Table { return $this->m_table; }
    public function getName() : string { return $this->m_name; }
    public function getMaxElements() : int { return $this->m_maxElements; }
    public function getTimeoutSeconds() : int { return $this->m_timeoutSeconds; }
}
