<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\SctpChunk;
use Programster\Nftables\Enums\SctpChunkField;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * An SCTP chunk, e.g. to check whether a packet has one (sctp chunk init exists), or one of its fields.
 *
 * Needs nft 1.0.2, and kernel 5.14 (or RHEL 8's, which has it backported).
 */
final readonly class SctpChunkExpression implements Expression
{
    private SctpChunk $m_chunk;

    // The field to read, or null to stand for the whole chunk, which only an existence check uses.
    private ?SctpChunkField $m_field;


    private function __construct(SctpChunk $chunk, ?SctpChunkField $field)
    {
        $this->m_chunk = $chunk;
        $this->m_field = $field;
    }


    /**
     * Create an expression for a whole chunk, to check whether the packet has it (see MatchFactory::createExistence()).
     *
     * @param SctpChunk $chunk - the chunk, e.g. SctpChunk::INIT.
     *
     * @return SctpChunkExpression
     */
    public static function create(SctpChunk $chunk) : SctpChunkExpression
    {
        return new SctpChunkExpression($chunk, null);
    }


    /**
     * Create an expression for one of a chunk's fields.
     *
     * @param SctpChunk $chunk - the chunk, e.g. SctpChunk::DATA.
     *
     * @param SctpChunkField $field - the field, e.g. SctpChunkField::TSN.
     *
     * @return SctpChunkExpression
     *
     * @throws BadArgumentException - if the chunk doesn't have that field.
     */
    public static function createField(SctpChunk $chunk, SctpChunkField $field) : SctpChunkExpression
    {
        if (!$field->getChunks()->contains($chunk))
        {
            throw new BadArgumentException("An SCTP {$chunk->value} chunk has no {$field->value} field.");
        }

        return new SctpChunkExpression($chunk, $field);
    }


    public function toJsonValue() : array
    {
        $chunk = ["name" => $this->m_chunk->value];

        if ($this->m_field !== null)
        {
            $chunk["field"] = $this->m_field->value;
        }

        return ["sctp chunk" => $chunk];
    }


    /**
     * Check whether this reads a field, rather than standing for the whole chunk.
     *
     * @return bool
     */
    public function isField() : bool
    {
        return $this->m_field !== null;
    }
}
