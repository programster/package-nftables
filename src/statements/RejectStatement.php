<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\IcmpRejectCode;
use Programster\Nftables\Enums\Icmpv6RejectCode;
use Programster\Nftables\Enums\IcmpxRejectCode;
use Programster\Nftables\Enums\RejectType;

/**
 * Drops the packet, and tells the sender, so they fail straight away instead of waiting to time out. Only works in
 * chains on the input, forward and output hooks (and prerouting, in recent kernels).
 */
final readonly class RejectStatement implements Statement
{
    private RejectType $m_type;
    private IcmpxRejectCode|IcmpRejectCode|Icmpv6RejectCode|null $m_code;


    private function __construct(RejectType $type, IcmpxRejectCode|IcmpRejectCode|Icmpv6RejectCode|null $code)
    {
        $this->m_type = $type;
        $this->m_code = $code;
    }


    /**
     * Reject with nftables' default reply: an ICMP port unreachable error (or a TCP reset, for TCP in inet tables).
     *
     * @return RejectStatement
     */
    public static function create() : RejectStatement
    {
        return new RejectStatement(RejectType::DEFAULT, null);
    }


    /**
     * Reject with a TCP reset, which is what a closed port replies with. Only applies to TCP packets.
     *
     * @return RejectStatement
     */
    public static function createTcpReset() : RejectStatement
    {
        return new RejectStatement(RejectType::TCP_RESET, null);
    }


    /**
     * Reject with an ICMP error that's worded the same for IPv4 and IPv6. inet tables only.
     *
     * @param IcmpxRejectCode $code - the error to reply with.
     *
     * @return RejectStatement
     */
    public static function createIcmpx(IcmpxRejectCode $code) : RejectStatement
    {
        return new RejectStatement(RejectType::ICMPX, $code);
    }


    /**
     * Reject IPv4 packets with an ICMP error. ip and inet tables only.
     *
     * @param IcmpRejectCode $code - the error to reply with.
     *
     * @return RejectStatement
     */
    public static function createIcmp(IcmpRejectCode $code) : RejectStatement
    {
        return new RejectStatement(RejectType::ICMP, $code);
    }


    /**
     * Reject IPv6 packets with an ICMPv6 error. ip6 and inet tables only.
     *
     * @param Icmpv6RejectCode $code - the error to reply with.
     *
     * @return RejectStatement
     */
    public static function createIcmpv6(Icmpv6RejectCode $code) : RejectStatement
    {
        return new RejectStatement(RejectType::ICMPV6, $code);
    }


    public function toArray() : array
    {
        $reject = [];

        if ($this->m_type !== RejectType::DEFAULT)
        {
            $reject["type"] = $this->m_type->value;
        }

        if ($this->m_code !== null)
        {
            $reject["expr"] = $this->m_code->value;
        }

        return ["reject" => (count($reject) === 0) ? null : $reject];
    }
}
