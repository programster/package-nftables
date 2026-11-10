<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The syslog level a LogStatement logs at.
 */
enum LogLevel : string
{
    case EMERG = "emerg";
    case ALERT = "alert";
    case CRIT = "crit";
    case ERR = "err";
    case WARN = "warn";
    case NOTICE = "notice";
    case INFO = "info";
    case DEBUG = "debug";
    case AUDIT = "audit";
}
