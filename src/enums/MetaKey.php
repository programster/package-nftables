<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A piece of packet metadata, for a MetaExpression.
 */
enum MetaKey : string
{
    case LENGTH = "length";
    case PROTOCOL = "protocol";
    case PRIORITY = "priority";
    case RANDOM = "random";
    case MARK = "mark";
    case IIF = "iif";
    case IIFNAME = "iifname";
    case IIFTYPE = "iiftype";
    case OIF = "oif";
    case OIFNAME = "oifname";
    case OIFTYPE = "oiftype";
    case SKUID = "skuid";
    case SKGID = "skgid";
    case NFTRACE = "nftrace";
    case RTCLASSID = "rtclassid";
    case IBRIPORT = "ibriport";
    case OBRIPORT = "obriport";
    case IBRIDGENAME = "ibridgename";
    case OBRIDGENAME = "obridgename";
    case PKTTYPE = "pkttype";
    case CPU = "cpu";
    case IIFGROUP = "iifgroup";
    case OIFGROUP = "oifgroup";
    case CGROUP = "cgroup";
    case NFPROTO = "nfproto";
    case L4PROTO = "l4proto";
    case SECPATH = "secpath";
    case TIME = "time";
    case DAY = "day";
    case HOUR = "hour";
}
