<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A connection state that a CtTimeout can set the timeout of. Each belongs to one protocol.
 */
enum CtTimeoutState : string
{
    case TCP_SYN_SENT = "syn_sent";
    case TCP_SYN_RECV = "syn_recv";
    case TCP_ESTABLISHED = "established";
    case TCP_FIN_WAIT = "fin_wait";
    case TCP_CLOSE_WAIT = "close_wait";
    case TCP_LAST_ACK = "last_ack";
    case TCP_TIME_WAIT = "time_wait";
    case TCP_CLOSE = "close";
    case TCP_SYN_SENT2 = "syn_sent2";

    // A connection with unacknowledged data that has been retransmitted.
    case TCP_RETRANS = "retrans";

    // A connection with unacknowledged data.
    case TCP_UNACK = "unack";

    // A UDP "connection" whose first packet hasn't had a reply.
    case UDP_UNREPLIED = "unreplied";

    // A UDP "connection" that has had a reply.
    case UDP_REPLIED = "replied";

    /**
     * Get the protocol the state belongs to.
     *
     * @return Protocol
     */
    public function getProtocol() : Protocol
    {
        return str_starts_with($this->name, "TCP_") ? Protocol::TCP : Protocol::UDP;
    }
}
