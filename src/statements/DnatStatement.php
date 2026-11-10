<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\NatFlag;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Expressions\MapLookupExpression;
use Programster\Nftables\PortRange;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\TableItemLib;

/**
 * Changes the packet's destination address (and optionally port), e.g. to forward a port to a machine behind
 * this one. Belongs in a nat chain on the prerouting (or output) hook. Translating the port needs a match on the
 * transport protocol (e.g. its destination port) earlier in the rule.
 */
final readonly class DnatStatement implements Statement, ReferencesTableItems
{
    private array $m_body;

    // The named maps it looks the address or port up in.
    private TableItemCollection $m_referencedItems;


    /**
     * Create a dnat statement. Use create() or createFromMap().
     *
     * @param array $body - the statement's body, in the form nftables expects.
     *
     * @param TableItemCollection $referencedItems - the named maps it looks the address or port up in.
     */
    private function __construct(array $body, TableItemCollection $referencedItems)
    {
        $this->m_body = $body;
        $this->m_referencedItems = $referencedItems;
    }


    /**
     * Create a dnat statement that translates to a fixed address.
     *
     * @param string $address - the IPv4 or IPv6 address to translate to.
     *
     * @param int|PortRange|null $port - the port to translate to, or a range to pick one from. Defaults to null,
     * which leaves the port alone.
     *
     * @param NatFlag ...$flags - how ports are chosen.
     *
     * @return DnatStatement
     *
     * @throws InvalidAddressException - if the address isn't an IP address.
     * @throws BadArgumentException - if the port isn't between 1 and 65535.
     */
    public static function create(string $address, int|PortRange|null $port = null, NatFlag ...$flags) : DnatStatement
    {
        return new DnatStatement(NatLib::createBody($address, $port, ...$flags), new TableItemCollection());
    }


    /**
     * Create a dnat statement that looks the address to translate to up in a map, e.g. a NamedMap from the port a
     * connection arrives on to the address of the machine to forward it to (tcp dport map @forwards). The map can also
     * give the port, as a concatenation of an address and port (a NamedMap whose value type is IPV4_ADDR .
     * INET_SERVICE, which needs nft 1.1.3, or an AnonymousMap of them, which needs nft 1.0.2). A packet whose key isn't
     * in the map doesn't match the rule, so isn't translated.
     *
     * @param IpVersion $ipVersion - the IP version of the addresses in the map, which nft needs to know.
     *
     * @param MapLookupExpression $address - the lookup that gives the address (or address and port).
     *
     * @param MapLookupExpression|null $port - optionally, a lookup that gives the port to translate to, e.g. from a
     * NamedMap of incoming ports to the ports to forward them to. Not needed if $address gives the port too. Defaults
     * to null, which leaves the port alone.
     *
     * @param NatFlag ...$flags - how ports are chosen.
     *
     * @return DnatStatement
     */
    public static function createFromMap(
        IpVersion $ipVersion,
        MapLookupExpression $address,
        ?MapLookupExpression $port = null,
        NatFlag ...$flags,
    ) : DnatStatement
    {
        $lookups = ($port === null) ? [$address] : [$address, $port];
        $referencedItems = TableItemLib::collectReferences(...$lookups);
        return new DnatStatement(NatLib::createMapBody($ipVersion, $address, $port, ...$flags), $referencedItems);
    }


    public function toArray() : array
    {
        return ["dnat" => $this->m_body];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return clone $this->m_referencedItems;
    }
}
