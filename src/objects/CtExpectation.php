<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\NetworkLib;
use Programster\Nftables\Table;

/**
 * A conntrack expectation: once a rule gives a connection one (ct expectation set "rtp"), conntrack expects a
 * connection back the other way, from the machine that was contacted to the one that contacted it, to a port, within a
 * time, and treats that connection as related to the first. It's a simple stand-in for a CtHelper, for a protocol that always opens its second connection on a known
 * port, so the second connection can be accepted with "ct state related" instead of opening the port to everyone.
 *
 * Needs nft 1.0.9, as older nft can't read one from JSON, and kernel 5.3.
 */
final readonly class CtExpectation extends NamedObject
{
    // The most the kernel allows for each of a connection's expectations.
    private const MAX_EXPECTATIONS = 255;

    private IpVersion $m_ipVersion;
    private Protocol $m_protocol;
    private int $m_port;
    private int $m_timeoutSeconds;
    private int $m_maxExpectations;


    /**
     * Create a conntrack expectation.
     *
     * @param string $name - the expectation's name, which must be unique among the expectations in its table.
     *
     * @param Table $table - the table it belongs to, which must be an ip, ip6 or inet table.
     *
     * @param IpVersion $ipVersion - the IP version of the connections it applies to.
     *
     * @param Protocol $protocol - the transport protocol of the expected connection.
     *
     * @param int $port - the port the expected connection goes to.
     *
     * @param int $timeoutSeconds - how long to wait for the expected connection.
     *
     * @param int $maxExpectations - the most expected connections each connection can have waiting at once, from 1 to
     * 255.
     *
     * @throws BadArgumentException - if the table isn't an ip, ip6 or inet table for that IP version, the port isn't
     * between 1 and 65535, the timeout isn't positive, the limit is out of range, or the name is empty or too long.
     */
    public function __construct(
        string $name,
        Table $table,
        IpVersion $ipVersion,
        Protocol $protocol,
        int $port,
        int $timeoutSeconds,
        int $maxExpectations,
    )
    {
        parent::__construct($name, $table);
        IpFamilyLib::assertIpFamily($table, "A ct expectation");
        NetworkLib::assertValidPort($port);
        $family = $table->getFamily();
        $isOtherVersion = ($family !== Family::INET && $family->value !== $ipVersion->value);

        if ($isOtherVersion)
        {
            $message = "A ct expectation in a {$family->value} table can't be for {$ipVersion->name} connections.";
            throw new BadArgumentException($message);
        }

        if ($timeoutSeconds < 1 || $maxExpectations < 1 || $maxExpectations > self::MAX_EXPECTATIONS)
        {
            $message = "A ct expectation needs a timeout of at least 1 second, and room for from 1 to "
                . self::MAX_EXPECTATIONS . " expected connections.";

            throw new BadArgumentException($message);
        }

        $this->m_ipVersion = $ipVersion;
        $this->m_protocol = $protocol;
        $this->m_port = $port;
        $this->m_timeoutSeconds = $timeoutSeconds;
        $this->m_maxExpectations = $maxExpectations;
    }


    public function toArray() : array
    {
        $expectation = [
            ...$this->getIdentifier(),
            "l3proto" => $this->m_ipVersion->value,
            "protocol" => $this->m_protocol->value,
            "dport" => $this->m_port,
            "timeout" => $this->m_timeoutSeconds * 1000,
            "size" => $this->m_maxExpectations,
        ];

        return ["ct expectation" => $expectation];
    }
}
