<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\Ipv6ExtensionHeader;
use Programster\Nftables\Enums\Ipv6ExtensionHeaderField;

/**
 * An IPv6 extension header, e.g. to drop fragmented IPv6 packets (exthdr frag exists), or one of its fields.
 */
final readonly class ExthdrExpression implements Expression
{
    private string $m_header;

    // The field to read, or "" to stand for the whole header, which only an existence check uses.
    private string $m_field;


    private function __construct(string $header, string $field)
    {
        $this->m_header = $header;
        $this->m_field = $field;
    }


    /**
     * Create an expression for a whole header, to check whether the packet has it (see
     * MatchFactory::createExistence()).
     *
     * @param Ipv6ExtensionHeader $header - the header, e.g. Ipv6ExtensionHeader::FRAGMENT.
     *
     * @return ExthdrExpression
     */
    public static function create(Ipv6ExtensionHeader $header) : ExthdrExpression
    {
        return new ExthdrExpression($header->value, "");
    }


    /**
     * Create an expression for one of a header's fields.
     *
     * @param Ipv6ExtensionHeaderField $field - the field, e.g. Ipv6ExtensionHeaderField::FRAG_MORE_FRAGMENTS.
     *
     * @return ExthdrExpression
     */
    public static function createField(Ipv6ExtensionHeaderField $field) : ExthdrExpression
    {
        return new ExthdrExpression($field->getHeader(), $field->getField());
    }


    public function toJsonValue() : array
    {
        $exthdr = ["name" => $this->m_header];

        if ($this->m_field !== "")
        {
            $exthdr["field"] = $this->m_field;
        }

        return ["exthdr" => $exthdr];
    }


    /**
     * Check whether this reads a field, rather than standing for the whole header.
     *
     * @return bool
     */
    public function isField() : bool
    {
        return $this->m_field !== "";
    }
}
