<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\TcpOption;
use Programster\Nftables\Enums\TcpOptionField;

/**
 * A TCP option, e.g. to check whether a packet has one (tcp option sack-perm exists), or one of its fields. A field can
 * also be changed with a MangleStatement, e.g. to clamp the maximum segment size (see RuleFactory::createMssClamp()).
 */
final readonly class TcpOptionExpression implements Expression
{
    private string $m_option;

    // The field to read, or "" to stand for the whole option, which only an existence check uses.
    private string $m_field;


    private function __construct(string $option, string $field)
    {
        $this->m_option = $option;
        $this->m_field = $field;
    }


    /**
     * Create an expression for a whole option, to check whether the packet has it (see
     * MatchFactory::createExistence()).
     *
     * @param TcpOption $option - the option, e.g. TcpOption::SACK_PERMITTED.
     *
     * @return TcpOptionExpression
     */
    public static function create(TcpOption $option) : TcpOptionExpression
    {
        return new TcpOptionExpression($option->value, "");
    }


    /**
     * Create an expression for one of an option's fields.
     *
     * @param TcpOptionField $field - the field, e.g. TcpOptionField::MAXSEG_SIZE.
     *
     * @return TcpOptionExpression
     */
    public static function createField(TcpOptionField $field) : TcpOptionExpression
    {
        return new TcpOptionExpression($field->getOption(), $field->getField());
    }


    public function toJsonValue() : array
    {
        $option = ["name" => $this->m_option];

        if ($this->m_field !== "")
        {
            $option["field"] = $this->m_field;
        }

        return ["tcp option" => $option];
    }


    /**
     * Check whether this reads a field, rather than standing for the whole option.
     *
     * @return bool
     */
    public function isField() : bool
    {
        return $this->m_field !== "";
    }
}
