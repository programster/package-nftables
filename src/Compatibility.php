<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Closure;
use Programster\Nftables\Collections\FeatureRequirementCollection;
use Programster\Nftables\Enums\NftablesTarget;
use Programster\Nftables\Exceptions\UnsupportedFeatureException;

/**
 * Knows which features need a newer nft (or kernel) than the oldest supported, and checks a ruleset's tables, chains,
 * sets and rules against its target. Each requirement was found by loading every feature into the nft of every
 * supported target (see testing/run-all-targets.sh), and is checked there by CompatibilityTest.
 *
 * Everything else works on every supported target, from nft 0.9.8 up.
 */
final class Compatibility
{
    private function __construct()
    {
    }


    /**
     * Check that a target can load a definition.
     *
     * @param array $definition - a table, chain, set or rule's toArray().
     *
     * @param NftablesTarget $target - where it will be loaded.
     *
     * @return void
     *
     * @throws UnsupportedFeatureException - if it uses a feature the target's nft or kernel can't handle.
     */
    public static function assertSupported(array $definition, NftablesTarget $target) : void
    {
        foreach (self::getRequirements() as $requirement)
        {
            if ($requirement->isUsedBy($definition))
            {
                self::assertTargetMeets($requirement, $target);
            }
        }
    }


    /**
     * Get every feature that needs a newer nft or kernel than the oldest supported.
     *
     * @return FeatureRequirementCollection
     */
    public static function getRequirements() : FeatureRequirementCollection
    {
        $rhel8 = [NftablesTarget::ROCKY_8, NftablesTarget::ALMA_8, NftablesTarget::RHEL_8];
        $rhel9 = [NftablesTarget::ROCKY_9, NftablesTarget::ALMA_9, NftablesTarget::RHEL_9];

        $isDormantTable = function (array $definition) : bool {
            return in_array("dormant", $definition["table"]["flags"] ?? [], true);
        };

        $isDeviceChain = function (array $definition) : bool {
            return in_array($definition["chain"]["hook"] ?? "", ["ingress", "egress"], true);
        };

        $isEgressChain = function (array $definition) : bool {
            return ($definition["chain"]["hook"] ?? "") === "egress";
        };

        $isFlowtable = function (array $definition) : bool {
            return isset($definition["flowtable"]);
        };

        $isMapOfConcatenations = function (array $definition) : bool {
            return is_array($definition["map"]["map"] ?? null);
        };

        $usesConcatenatedAnonymousMap = function (array $definition) : bool {
            $found = false;

            foreach (self::findInRule($definition, "map") as $lookup)
            {
                foreach (is_array($lookup) ? ($lookup["data"]["set"] ?? []) : [] as $element)
                {
                    $found = $found || isset($element[1]["concat"]);
                }
            }

            return $found;
        };

        $usesSetUpdateStatements = function (array $definition) : bool {
            $found = false;

            foreach (self::findInRule($definition, "set") as $set)
            {
                $found = $found || isset($set["stmt"]);
            }

            return $found;
        };

        $isCtTimeout = function (array $definition) : bool {
            return isset($definition["ct timeout"]);
        };

        $isNamedSynproxy = function (array $definition) : bool {
            return isset($definition["synproxy"]["name"]);
        };

        // Each of these checks whether a rule uses a kind of statement or expression.
        $uses = function (string $key) : Closure {
            $usesKey = function (array $definition) use ($key) : bool {
                return count(self::findInRule($definition, $key)) > 0;
            };

            return $usesKey;
        };

        // nft 1.0.9 and older read the JSON, but silently drop the flag, so the table's rules stay on. Red Hat
        // backported it to the nft 1.0.9 in 9.x, though.
        $dormant = new FeatureRequirement("The dormant table flag", "1.1.3", "", $isDormantTable, ...$rhel9);

        // Older nft can't read a chain's device from JSON (0.9.8 and 1.0.4 fail, and 1.0.2 crashes).
        $device = new FeatureRequirement("A chain on the ingress or egress hook", "1.0.6", "", $isDeviceChain);

        // Red Hat backported the hook to RHEL 9's kernel 5.14 (CONFIG_NETFILTER_EGRESS, in a fully updated 9.x).
        $egress = new FeatureRequirement("A chain on the egress hook", "1.0.6", "5.16", $isEgressChain, ...$rhel9);

        // Older nft can't read a flowtable's devices from JSON, as for a chain's (0.9.8 crashes, and 1.0.2 and 1.0.4
        // silently drop them).
        $flowtable = new FeatureRequirement("A flowtable", "1.0.6", "", $isFlowtable);

        // Older nft crashes, or silently drops the map. Red Hat backported the fix to the nft 1.0.9 in 9.x.
        $description = "A named map whose values are concatenations";
        $concatenatedMap = new FeatureRequirement($description, "1.1.3", "", $isMapOfConcatenations, ...$rhel9);

        // 0.9.8 can't read them.
        $description = "An anonymous map whose values are concatenations";
        $concatenatedAnonymousMap = new FeatureRequirement($description, "1.0.2", "", $usesConcatenatedAnonymousMap);

        // Older nft silently drops the statements, leaving a plain set update.
        $description = "A set update with statements (a meter)";
        $setUpdateStatements = new FeatureRequirement($description, "1.0.6", "", $usesSetUpdateStatements);

        // 0.9.8 crashes, and 1.0.2 to 1.0.6 silently drop the timeouts.
        $ctTimeout = new FeatureRequirement("A ct timeout", "1.0.9", "4.19", $isCtTimeout);

        // Older nft can't read one from JSON. Red Hat backported it to the nft 1.0.9 in 9.x.
        $namedSynproxy = new FeatureRequirement("A named synproxy", "1.1.3", "5.3", $isNamedSynproxy, ...$rhel9);

        $synproxy = new FeatureRequirement("A synproxy", "0.9.8", "5.3", $uses("synproxy"));

        // RHEL 8's kernel has it backported.
        $tproxy = new FeatureRequirement("A transparent proxy", "0.9.8", "4.19", $uses("tproxy"), ...$rhel8);

        $osf = new FeatureRequirement("Operating system fingerprinting", "0.9.8", "4.19", $uses("osf"));

        // Older nft can't read the statement from JSON.
        $secmark = new FeatureRequirement("Setting a security mark", "1.0.6", "", $uses("secmark"));

        // RHEL 8's kernel has it backported.
        $sctpChunk = new FeatureRequirement("An SCTP chunk", "1.0.2", "5.14", $uses("sctp chunk"), ...$rhel8);

        $requirements = [
            $dormant,
            $device,
            $egress,
            $flowtable,
            $concatenatedMap,
            $concatenatedAnonymousMap,
            $setUpdateStatements,
            $ctTimeout,
            $namedSynproxy,
            $synproxy,
            $tproxy,
            $osf,
            $secmark,
            $sctpChunk,
        ];

        return new FeatureRequirementCollection($requirements);
    }


    /**
     * Check that a target meets a requirement.
     *
     * @param FeatureRequirement $requirement - the requirement.
     *
     * @param NftablesTarget $target - the target.
     *
     * @return void
     *
     * @throws UnsupportedFeatureException - if it doesn't.
     */
    private static function assertTargetMeets(FeatureRequirement $requirement, NftablesTarget $target) : void
    {
        $nftablesVersion = $requirement->getNftablesVersion();
        $kernelVersion = $requirement->getKernelVersion();
        $targetDescription = $target->getDescription();
        $hint = "Pass a newer NftablesTarget to the Ruleset to use it.";

        if (!$requirement->isInNftablesOf($target))
        {
            $needs = "{$requirement->getDescription()} needs nft {$nftablesVersion} or later";
            throw new UnsupportedFeatureException("{$needs}, but this ruleset is for {$targetDescription}. {$hint}");
        }

        if (!$requirement->isInKernelOf($target))
        {
            $needs = "{$requirement->getDescription()} needs kernel {$kernelVersion} or later";
            throw new UnsupportedFeatureException("{$needs}, which {$targetDescription} doesn't have. {$hint}");
        }
    }


    /**
     * Find every value stored under a key, at any depth, in a rule's definition.
     *
     * @param array $definition - a table, chain, set or rule's toArray(). Only a rule's is searched.
     *
     * @param string $key - the key, e.g. "tproxy".
     *
     * @return array - the values, or nothing if the definition isn't a rule's.
     */
    private static function findInRule(array $definition, string $key) : array
    {
        $values = [];
        $toSearch = isset($definition["rule"]) ? [$definition["rule"]] : [];

        while (count($toSearch) > 0)
        {
            $current = array_pop($toSearch);

            foreach ($current as $currentKey => $value)
            {
                if ($currentKey === $key)
                {
                    $values[] = $value;
                }

                if (is_array($value))
                {
                    $toSearch[] = $value;
                }
            }
        }

        return $values;
    }
}
