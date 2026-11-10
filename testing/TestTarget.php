<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use Programster\Nftables\Enums\NftablesTarget;
use RuntimeException;

/**
 * Works out which NftablesTarget the tests are running on, so they build rulesets this machine's nft can load, and
 * know which features to expect to work.
 */
final class TestTarget
{
    // Found the first time it's needed (see detect()).
    private static ?NftablesTarget $s_target = null;


    private function __construct()
    {
    }


    /**
     * Get the target the tests are running on: the one named by NFTABLES_TEST_TARGET (e.g. "DEBIAN_11", as the
     * Docker runs set), or else the newest version case that isn't newer than this machine's nft. Without nft, it's
     * the newest target, for the tests that don't load anything.
     *
     * @return NftablesTarget
     *
     * @throws RuntimeException - if NFTABLES_TEST_TARGET isn't the name of a target.
     */
    public static function detect() : NftablesTarget
    {
        if (self::$s_target === null)
        {
            $name = (string)getenv("NFTABLES_TEST_TARGET");

            self::$s_target = ($name !== "")
                ? self::findByName($name)
                : self::findForVersion(NftNamespace::findNftablesVersion());
        }

        return self::$s_target;
    }


    /**
     * Check whether the nft the tests are running on words its listings the way the feature tests expect (nft 1.1 and
     * later), as older versions word some things differently (e.g. "queue num 0" for "queue to 0").
     *
     * @return bool
     */
    public static function hasCurrentListings() : bool
    {
        return self::detect()->hasNftablesAtLeast("1.1.3");
    }


    /**
     * Check whether the nft the tests are running on is the version whose listings the docs show (nft 1.1.3, as in
     * Debian 13), so the docs' listings can be compared with its own word for word.
     *
     * @return bool
     */
    public static function isDocsVersion() : bool
    {
        return self::detect()->getNftablesVersion() === "1.1.3";
    }


    /**
     * Get a target by its case name.
     *
     * @param string $name - e.g. "DEBIAN_11".
     *
     * @return NftablesTarget
     *
     * @throws RuntimeException - if there's no target with that name.
     */
    private static function findByName(string $name) : NftablesTarget
    {
        $found = null;

        foreach (NftablesTarget::cases() as $target)
        {
            if ($found === null && $target->name === $name)
            {
                $found = $target;
            }
        }

        if ($found === null)
        {
            throw new RuntimeException("NFTABLES_TEST_TARGET is \"{$name}\", which isn't an NftablesTarget.");
        }

        return $found;
    }


    /**
     * Get the newest version target that isn't newer than an nft version.
     *
     * @param string $version - the nft version, e.g. "1.0.7", or "" if nft isn't available.
     *
     * @return NftablesTarget
     */
    private static function findForVersion(string $version) : NftablesTarget
    {
        $best = NftablesTarget::NFTABLES_0_9_8;

        foreach (NftablesTarget::cases() as $target)
        {
            $targetVersion = $target->getNftablesVersion();

            if (
                   str_starts_with($target->name, "NFTABLES_")
                && ($version === "" || version_compare($targetVersion, $version, "<="))
                && version_compare($targetVersion, $best->getNftablesVersion(), ">")
            )
            {
                $best = $target;
            }
        }

        return $best;
    }
}
