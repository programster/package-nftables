<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\ChainLib;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\SynproxyFlag;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Answers new TCP connections on a server's behalf with SYN cookies, and only passes a connection on to the server once
 * the client has completed the handshake, so a SYN flood (e.g. from spoofed addresses) never reaches the server or
 * fills conntrack. Only works in a filter chain on the input or forward hook.
 *
 * It needs the rest of the setup to work, as shown in docs/statements.md: SYN packets to the port need notrack in a
 * raw prerouting chain, the synproxy rule then matches "ct state invalid,untracked", and a later rule drops the invalid
 * packets left over. For a synproxy that several rules share, use a NamedSynproxy.
 *
 * Needs kernel 5.3, so isn't available on RHEL 8.
 */
final readonly class SynproxyStatement implements Statement, ChainRestricted
{
    // The largest window scale TCP allows (RFC 7323).
    private const MAX_WINDOW_SCALE = 14;

    private int $m_maximumSegmentSize;
    private int $m_windowScale;

    /** @var string[] - the flags' values, without duplicates. */
    private array $m_flags;


    /**
     * Create a synproxy statement. Its values are what the proxy tells the client on the server's behalf, so they must
     * match what the server itself would offer, or connections will misbehave.
     *
     * @param int $maximumSegmentSize - the server's maximum segment size, e.g. 1460 for a server on Ethernet.
     *
     * @param int $windowScale - the server's window scale, from 0 to 14, e.g. 7, which Linux servers usually use.
     *
     * @param SynproxyFlag ...$flags - the TCP options the server supports, which most do.
     *
     * @throws BadArgumentException - if the maximum segment size isn't from 1 to 65535, or the window scale isn't from
     * 0 to 14.
     */
    public function __construct(int $maximumSegmentSize, int $windowScale, SynproxyFlag ...$flags)
    {
        if ($maximumSegmentSize < 1 || $maximumSegmentSize > 65535)
        {
            throw new BadArgumentException("A maximum segment size must be from 1 to 65535.");
        }

        if ($windowScale < 0 || $windowScale > self::MAX_WINDOW_SCALE)
        {
            throw new BadArgumentException("A window scale must be from 0 to " . self::MAX_WINDOW_SCALE . ".");
        }

        $this->m_maximumSegmentSize = $maximumSegmentSize;
        $this->m_windowScale = $windowScale;
        $this->m_flags = array_values(array_unique(array_column($flags, "value")));
    }


    public function toArray() : array
    {
        $synproxy = ["mss" => $this->m_maximumSegmentSize, "wscale" => $this->m_windowScale];

        if (count($this->m_flags) > 0)
        {
            $synproxy["flags"] = $this->m_flags;
        }

        return ["synproxy" => $synproxy];
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        ChainLib::assertChainIs($chain, ChainType::FILTER, "use a synproxy", ChainHook::INPUT, ChainHook::FORWARD);
    }
}
