<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\SocketKey;

/**
 * Something about the local socket a packet belongs to, if there is one (socket transparent), e.g. to accept packets
 * for an already open transparent proxy connection without sending them through the TproxyStatement again. A packet
 * with no local socket doesn't match.
 *
 * Only works on the prerouting, input and output hooks. Its MARK key needs kernel 4.19, and WILDCARD kernel 5.6, so
 * neither is available on RHEL 8.
 */
final readonly class SocketExpression implements Expression
{
    private SocketKey $m_key;


    /**
     * Create a socket expression.
     *
     * @param SocketKey $key - what to read from the socket.
     */
    public function __construct(SocketKey $key)
    {
        $this->m_key = $key;
    }


    public function toJsonValue() : array
    {
        return ["socket" => ["key" => $this->m_key->value]];
    }
}
