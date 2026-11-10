<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Collections\CtTimeoutPolicyCollection;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Table;

/**
 * Conntrack timeouts for the connections a rule assigns it to (ct timeout set "long-tcp"), in place of the system's
 * defaults (the net.netfilter.nf_conntrack_*_timeout sysctls), e.g. to keep idle established TCP connections to one
 * service for longer, without changing them for every connection.
 *
 * The rule must be in a chain that runs before conntrack sees the connection's first packet (priority below -200),
 * e.g. a filter chain on the prerouting hook with Priority::RAW.
 *
 * Needs nft 1.0.9, as older nft crashes, or silently drops the timeouts, and kernel 4.19.
 */
final readonly class CtTimeout extends NamedObject
{
    // One per state.
    private CtTimeoutPolicyCollection $m_policies;


    /**
     * Create a conntrack timeout.
     *
     * @param string $name - the timeout's name, which must be unique among the timeouts in its table.
     *
     * @param Table $table - the table it belongs to, which must be an ip, ip6 or inet table.
     *
     * @param CtTimeoutPolicy ...$policies - the timeouts, for states of one protocol (e.g. all TCP). States not given
     * keep the system's default.
     *
     * @throws BadArgumentException - if the table isn't an ip, ip6 or inet table, there are no policies, they're for
     * more than one protocol, a state is given twice, or the name is empty or too long.
     */
    public function __construct(string $name, Table $table, CtTimeoutPolicy ...$policies)
    {
        parent::__construct($name, $table);
        IpFamilyLib::assertIpFamily($table, "A ct timeout");
        $protocols = [];
        $states = [];

        foreach ($policies as $policy)
        {
            $protocols[$policy->getState()->getProtocol()->value] = true;
            $states[$policy->getState()->value] = true;
        }

        if (count($protocols) !== 1)
        {
            throw new BadArgumentException("A ct timeout needs timeouts for the states of exactly one protocol.");
        }

        if (count($states) !== count($policies))
        {
            throw new BadArgumentException("A ct timeout can only have one timeout for each state.");
        }

        $this->m_policies = new CtTimeoutPolicyCollection(array_values($policies));
    }


    public function toArray() : array
    {
        $policy = [];

        foreach ($this->m_policies as $statePolicy)
        {
            $policy[$statePolicy->getState()->value] = $statePolicy->getSeconds();
        }

        $timeout = [
            ...$this->getIdentifier(),
            "protocol" => $this->m_policies->first()->getState()->getProtocol()->value,
            "l3proto" => $this->m_table->getFamily()->value,
            "policy" => $policy,
        ];

        return ["ct timeout" => $timeout];
    }
}
