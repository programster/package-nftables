<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Enums\CtHelperType;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Table;

/**
 * A conntrack helper, for a protocol whose connections open further connections, e.g. FTP's data connections. Once a
 * rule assigns it to a connection (ct helper set "ftp"), the kernel reads that connection to recognise the ones it
 * opens as related, and to NAT them to match.
 *
 * The kernel doesn't assign helpers by itself, and helpers have been the target of attacks, so only assign one to
 * the connections that need it, e.g. those to port 21 of the FTP server you're forwarding to. The rule must be in a
 * chain that runs after conntrack (priority above -200), e.g. a filter chain on the prerouting hook with
 * Priority::FILTER, and the "related" connections still need accepting in the forward or input chain.
 */
final readonly class CtHelper extends NamedObject
{
    private CtHelperType $m_type;


    /**
     * Create a conntrack helper.
     *
     * @param string $name - the helper's name, which must be unique among the helpers in its table.
     *
     * @param Table $table - the table it belongs to, which must be an ip, ip6 or inet table.
     *
     * @param CtHelperType $type - the protocol it understands.
     *
     * @throws BadArgumentException - if the table isn't an ip, ip6 or inet table, or the name is empty or too long.
     */
    public function __construct(string $name, Table $table, CtHelperType $type)
    {
        parent::__construct($name, $table);
        IpFamilyLib::assertIpFamily($table, "A ct helper");
        $this->m_type = $type;
    }


    public function toArray() : array
    {
        $helper = [
            ...$this->getIdentifier(),
            "type" => $this->m_type->getHelperName(),
            "protocol" => $this->m_type->getProtocol()->value,
            "l3proto" => $this->m_table->getFamily()->value,
        ];

        return ["ct helper" => $helper];
    }
}
