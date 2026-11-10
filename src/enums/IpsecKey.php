<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which part of an IPsec security association an IpsecExpression reads. The tunnel's addresses are read with
 * IpsecExpression::createAddress() instead.
 */
enum IpsecKey : string
{
    // The request ID of the policy (reqid), which ties it to its security associations.
    case REQID = "reqid";

    // The security parameter index (SPI) of the security association.
    case SPI = "spi";
}
