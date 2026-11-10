<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What an OsfExpression gives for the operating system a packet looks like it came from.
 */
enum OsfKey : string
{
    // Its name, e.g. "Linux", or "unknown" if it doesn't match a fingerprint.
    case NAME = "name";

    // Its name and version, e.g. "Linux:4.20".
    case VERSION = "version";
}
