<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\NatFlag;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\PortRange;

/**
 * Changes the packet's source address to the address of the interface it's leaving by, so machines behind this one
 * appear to come from it. Like SnatStatement, but follows the interface's address if it changes. Belongs in a nat
 * chain on the postrouting hook.
 */
final readonly class MasqueradeStatement implements Statement
{
    private array $m_body;


    /**
     * Create a masquerade statement.
     *
     * @param int|PortRange|null $port - optionally, the source port to use, or a range to pick one from. Defaults to
     * null, which leaves the port alone where possible. Needs a match on the transport protocol earlier in the rule.
     *
     * @param NatFlag ...$flags - how ports are chosen.
     *
     * @throws BadArgumentException - if the port isn't between 1 and 65535.
     */
    public function __construct(int|PortRange|null $port = null, NatFlag ...$flags)
    {
        $this->m_body = NatLib::createBody("", $port, ...$flags);
    }


    public function toArray() : array
    {
        return ["masquerade" => (count($this->m_body) === 0) ? null : $this->m_body];
    }
}
