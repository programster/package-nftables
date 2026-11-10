<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

use Programster\Nftables\Collections\SctpChunkCollection;

/**
 * A field of an SCTP chunk, for an SctpChunkExpression. TYPE, FLAGS and LENGTH are in every chunk. Each of the others
 * is only in the chunks getChunks() lists.
 */
enum SctpChunkField : string
{
    case TYPE = "type";
    case FLAGS = "flags";
    case LENGTH = "length";
    case TSN = "tsn";
    case STREAM = "stream";
    case SSN = "ssn";
    case PPID = "ppid";
    case INIT_TAG = "init-tag";
    case A_RWND = "a-rwnd";
    case NUM_OUTBOUND_STREAMS = "num-outbound-streams";
    case NUM_INBOUND_STREAMS = "num-inbound-streams";
    case INITIAL_TSN = "initial-tsn";
    case CUM_TSN_ACK = "cum-tsn-ack";
    case NUM_GAP_ACK_BLOCKS = "num-gap-ack-blocks";
    case NUM_DUP_TSNS = "num-dup-tsns";
    case LOWEST_TSN = "lowest-tsn";
    case SEQNO = "seqno";
    case NEW_CUM_TSN = "new-cum-tsn";

    /**
     * Get the chunks that have this field.
     *
     * @return SctpChunkCollection
     */
    public function getChunks() : SctpChunkCollection
    {
        $init = [SctpChunk::INIT, SctpChunk::INIT_ACK];

        $chunks = match ($this) {
            self::TYPE, self::FLAGS, self::LENGTH => SctpChunk::cases(),
            self::TSN, self::STREAM, self::SSN, self::PPID => [SctpChunk::DATA],
            self::INIT_TAG, self::NUM_OUTBOUND_STREAMS, self::NUM_INBOUND_STREAMS, self::INITIAL_TSN => $init,
            self::A_RWND => [...$init, SctpChunk::SACK],
            self::CUM_TSN_ACK => [SctpChunk::SACK, SctpChunk::SHUTDOWN],
            self::NUM_GAP_ACK_BLOCKS, self::NUM_DUP_TSNS => [SctpChunk::SACK],
            self::LOWEST_TSN => [SctpChunk::ECNE, SctpChunk::CWR],
            self::SEQNO => [SctpChunk::ASCONF_ACK, SctpChunk::ASCONF],
            self::NEW_CUM_TSN => [SctpChunk::FORWARD_TSN],
        };

        return new SctpChunkCollection($chunks);
    }
}
