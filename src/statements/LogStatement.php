<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\LogFlagCollection;
use Programster\Nftables\Enums\LogFlag;
use Programster\Nftables\Enums\LogLevel;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Logs the packet to the kernel log, then carries on with the rest of the rule.
 */
final readonly class LogStatement implements Statement
{
    // The kernel's limit, which includes a terminating null byte.
    private const MAX_PREFIX_BYTES = 127;

    private string $m_prefix;
    private LogLevel $m_level;

    // Without duplicates.
    private LogFlagCollection $m_flags;


    /**
     * Create a log statement.
     *
     * @param string $prefix - optionally, text to start each log entry with, to make them easy to find. Defaults to
     * none.
     *
     * @param LogLevel $level - the syslog level to log at. Defaults to WARN, as nftables does.
     *
     * @param LogFlag ...$flags - extra information to include in each entry.
     *
     * @throws BadArgumentException - if the prefix is longer than 127 bytes.
     */
    public function __construct(string $prefix = "", LogLevel $level = LogLevel::WARN, LogFlag ...$flags)
    {
        if (strlen($prefix) > self::MAX_PREFIX_BYTES)
        {
            throw new BadArgumentException("A log prefix can be at most " . self::MAX_PREFIX_BYTES . " bytes long.");
        }

        $this->m_prefix = $prefix;
        $this->m_level = $level;
        // Keyed by value, to leave out duplicates.
        $uniqueFlags = [];

        foreach ($flags as $flag)
        {
            $uniqueFlags[$flag->value] = $flag;
        }

        $this->m_flags = new LogFlagCollection(array_values($uniqueFlags));
    }


    public function toArray() : array
    {
        $log = ["level" => $this->m_level->value];

        if ($this->m_prefix !== "")
        {
            $log["prefix"] = $this->m_prefix;
        }

        if (count($this->m_flags) > 0)
        {
            $log["flags"] = $this->m_flags->column("value");
        }

        return ["log" => $log];
    }
}
