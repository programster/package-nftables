<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A type of SCTP chunk, for an SctpChunkExpression.
 */
enum SctpChunk : string
{
    case DATA = "data";
    case INIT = "init";
    case INIT_ACK = "init-ack";
    case SACK = "sack";
    case HEARTBEAT = "heartbeat";
    case HEARTBEAT_ACK = "heartbeat-ack";
    case ABORT = "abort";
    case SHUTDOWN = "shutdown";
    case SHUTDOWN_ACK = "shutdown-ack";
    case ERROR = "error";
    case COOKIE_ECHO = "cookie-echo";
    case COOKIE_ACK = "cookie-ack";
    case ECNE = "ecne";
    case CWR = "cwr";
    case SHUTDOWN_COMPLETE = "shutdown-complete";
    case ASCONF_ACK = "asconf-ack";
    case FORWARD_TSN = "forward-tsn";
    case ASCONF = "asconf";
}
