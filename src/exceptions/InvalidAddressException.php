<?php

declare(strict_types=1);

namespace Programster\Nftables\Exceptions;

/**
 * Thrown when a string isn't an IP address or a network CIDR (one whose host bits are all zero, e.g. 10.0.0.0/8 rather
 * than 10.0.0.1/8), where one was needed.
 */
class InvalidAddressException extends BadArgumentException
{
}
