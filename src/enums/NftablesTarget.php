<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Where a ruleset will be loaded: an operating system release, or an nftables version. A Ruleset throws if it's given
 * something that target's nft can't load (or would silently ignore), rather than the problem only showing up on the
 * server. The JSON itself is the same for every target, as it's always written in a form every version reads.
 *
 * - The operating system cases are the easiest to pick. They also know the release's kernel, so they catch features
 *   that its kernel can't do, even though its nft could.
 *
 * - The version cases are for anything else. Pick the newest one that isn't newer than the server's nft
 *   ("nft --version"). They only check the nft version, so they can't catch kernel limits.
 *
 * The Rocky Linux, AlmaLinux and RHEL cases are for an up to date release, e.g. 8.10 for 8. Their early 8.x point
 * releases shipped nft 0.9.3, which is older than this package supports.
 */
enum NftablesTarget
{
    case DEBIAN_11;
    case DEBIAN_12;
    case DEBIAN_13;
    case UBUNTU_22_04;
    case UBUNTU_24_04;
    case UBUNTU_26_04;
    case ROCKY_8;
    case ROCKY_9;
    case ROCKY_10;
    case ALMA_8;
    case ALMA_9;
    case ALMA_10;
    case RHEL_8;
    case RHEL_9;
    case RHEL_10;

    case NFTABLES_0_9_8;
    case NFTABLES_1_0_2;
    case NFTABLES_1_0_4;
    case NFTABLES_1_0_6;
    case NFTABLES_1_0_9;
    case NFTABLES_1_1_3;
    case NFTABLES_1_1_5;
    case NFTABLES_1_1_6;


    /**
     * Get the version of nft this target has.
     *
     * @return string - e.g. "1.0.6".
     */
    public function getNftablesVersion() : string
    {
        return match ($this) {
            self::DEBIAN_11, self::NFTABLES_0_9_8 => "0.9.8",
            self::UBUNTU_22_04, self::NFTABLES_1_0_2 => "1.0.2",
            self::ROCKY_8, self::ALMA_8, self::RHEL_8, self::NFTABLES_1_0_4 => "1.0.4",
            self::DEBIAN_12, self::NFTABLES_1_0_6 => "1.0.6",
            self::UBUNTU_24_04, self::ROCKY_9, self::ALMA_9, self::RHEL_9, self::NFTABLES_1_0_9 => "1.0.9",
            self::DEBIAN_13, self::NFTABLES_1_1_3 => "1.1.3",
            self::ROCKY_10, self::ALMA_10, self::RHEL_10, self::NFTABLES_1_1_5 => "1.1.5",
            self::UBUNTU_26_04, self::NFTABLES_1_1_6 => "1.1.6",
        };
    }


    /**
     * Check whether this target's nft is at least a version.
     *
     * @param string $version - the version, e.g. "1.0.6".
     *
     * @return bool
     */
    public function hasNftablesAtLeast(string $version) : bool
    {
        return version_compare($this->getNftablesVersion(), $version, ">=");
    }


    /**
     * Check whether this target's kernel is at least a version. Only the operating system cases know their kernel, so
     * the version cases always pass.
     *
     * @param string $version - the kernel version, e.g. "5.16".
     *
     * @return bool
     */
    public function hasKernelAtLeast(string $version) : bool
    {
        // The oldest kernel each release ships (e.g. Ubuntu's general availability kernel, not its newer HWE ones).
        $kernel = match ($this) {
            self::DEBIAN_11 => "5.10",
            self::DEBIAN_12 => "6.1",
            self::DEBIAN_13 => "6.12",
            self::UBUNTU_22_04 => "5.15",
            self::UBUNTU_24_04, self::UBUNTU_26_04 => "6.8",
            self::ROCKY_8, self::ALMA_8, self::RHEL_8 => "4.18",
            self::ROCKY_9, self::ALMA_9, self::RHEL_9 => "5.14",
            self::ROCKY_10, self::ALMA_10, self::RHEL_10 => "6.12",
            default => "",
        };

        return ($kernel === "") || version_compare($kernel, $version, ">=");
    }


    /**
     * Get a description of the target, for messages.
     *
     * @return string - e.g. "Debian 12 (nft 1.0.6)" or "nft 1.0.6".
     */
    public function getDescription() : string
    {
        $parts = explode("_", $this->name);
        $nft = "nft {$this->getNftablesVersion()}";

        $system = match ($parts[0]) {
            "DEBIAN" => "Debian {$parts[1]}",
            "UBUNTU" => "Ubuntu {$parts[1]}.{$parts[2]}",
            "ROCKY" => "Rocky Linux {$parts[1]}",
            "ALMA" => "AlmaLinux {$parts[1]}",
            "RHEL" => "RHEL {$parts[1]}",
            default => "",
        };

        return ($system === "") ? $nft : "{$system} ({$nft})";
    }
}
