<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\NatFlag;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\PortRange;

/**
 * Sends the packet to this machine, optionally on a different port, e.g. to send port 80 to a local proxy on port 8080.
 * Belongs in a nat chain on the prerouting or output hook.
 */
final readonly class RedirectStatement implements Statement
{
    private array $m_body;


    /**
     * Create a redirect statement.
     *
     * @param int|PortRange|null $port - the local port to send it to, or a range to pick one from. Defaults to null,
     * which keeps its port. Needs a match on the transport protocol earlier in the rule.
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
        return ["redirect" => (count($this->m_body) === 0) ? null : $this->m_body];
    }
}
