<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A bitwise operation, for a BinaryOperationExpression.
 */
enum BinaryOperator : string
{
    case AND = "&";
    case OR = "|";
    case XOR = "^";
    case SHIFT_LEFT = "<<";
    case SHIFT_RIGHT = ">>";
}
