<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\QueueFailMode;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Hands the packet to a program on this machine (e.g. an intrusion prevention system such as Suricata), which decides
 * whether it's accepted or dropped.
 *
 * What happens when no program is reading the queue has to be chosen explicitly: either nothing gets through (DROP),
 * or everything does, unchecked (ACCEPT).
 */
final readonly class QueueStatement implements Statement
{
    private const MAX_QUEUE = 65535;

    private QueueFailMode $m_failMode;
    private int $m_firstQueue;
    private int $m_lastQueue;


    private function __construct(QueueFailMode $failMode, int $firstQueue, int $lastQueue)
    {
        if ($firstQueue < 0 || $lastQueue > self::MAX_QUEUE || $firstQueue > $lastQueue)
        {
            throw new BadArgumentException("Queue numbers go from 0 to 65535, and the first can't be above the last.");
        }

        $this->m_failMode = $failMode;
        $this->m_firstQueue = $firstQueue;
        $this->m_lastQueue = $lastQueue;
    }


    /**
     * Queue packets to a single queue.
     *
     * @param QueueFailMode $whenNothingIsListening - what happens to the packets if no program is reading the queue.
     *
     * @param int $queueNumber - the queue, from 0 to 65535. Defaults to 0.
     *
     * @return QueueStatement
     *
     * @throws BadArgumentException - if the queue number is out of range.
     */
    public static function create(QueueFailMode $whenNothingIsListening, int $queueNumber = 0) : QueueStatement
    {
        return new QueueStatement($whenNothingIsListening, $queueNumber, $queueNumber);
    }


    /**
     * Spread packets across a range of queues, so several copies of a program can share the work. Each connection
     * stays on one queue.
     *
     * @param QueueFailMode $whenNothingIsListening - what happens to the packets if no program is reading the queue.
     *
     * @param int $firstQueue - the first queue in the range.
     *
     * @param int $lastQueue - the last queue in the range.
     *
     * @return QueueStatement
     *
     * @throws BadArgumentException - if the queue numbers are out of range, or the wrong way round.
     */
    public static function createSpread(
        QueueFailMode $whenNothingIsListening,
        int $firstQueue,
        int $lastQueue,
    ) : QueueStatement
    {
        return new QueueStatement($whenNothingIsListening, $firstQueue, $lastQueue);
    }


    public function toArray() : array
    {
        $isRange = ($this->m_firstQueue !== $this->m_lastQueue);
        $queue = ["num" => $isRange ? ["range" => [$this->m_firstQueue, $this->m_lastQueue]] : $this->m_firstQueue];
        $flags = [];

        if ($this->m_failMode === QueueFailMode::ACCEPT)
        {
            $flags[] = "bypass";
        }

        if ($isRange)
        {
            $flags[] = "fanout";
        }

        if (count($flags) > 0)
        {
            $queue["flags"] = $flags;
        }

        return ["queue" => $queue];
    }
}
