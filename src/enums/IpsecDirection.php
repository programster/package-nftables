<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which IPsec processing an IpsecExpression reads about.
 */
enum IpsecDirection : string
{
    // The decryption a packet arrived through. Only on the prerouting, input and forward hooks.
    case IN = "in";

    // The encryption a packet will leave through. Only on the forward, output and postrouting hooks.
    case OUT = "out";
}
