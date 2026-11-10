<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Closure;
use Programster\Nftables\Collections\NftablesTargetCollection;
use Programster\Nftables\Enums\NftablesTarget;

/**
 * A feature that needs a newer nft (or kernel) than the oldest this package supports, and how to spot it in a table,
 * chain, set or rule's JSON. See Compatibility.
 *
 * @internal
 */
final readonly class FeatureRequirement
{
    private string $m_description;
    private string $m_nftablesVersion;
    private string $m_kernelVersion;
    private Closure $m_isUsedBy;

    private NftablesTargetCollection $m_alsoSupportedBy;


    /**
     * Create a requirement.
     *
     * @param string $description - what the feature is, to start the exception's message, e.g. "The dormant flag".
     *
     * @param string $nftablesVersion - the oldest nft that handles it, e.g. "1.1.3".
     *
     * @param string $kernelVersion - the oldest kernel that handles it, or "" if any supported one does.
     *
     * @param Closure $isUsedBy - given a definition's JSON (as an array), returns true if it uses the feature.
     *
     * @param NftablesTarget ...$alsoSupportedBy - operating system targets that have the feature although their nft
     * or kernel is older, because their distribution backported it. They're never refused it.
     */
    public function __construct(
        string $description,
        string $nftablesVersion,
        string $kernelVersion,
        Closure $isUsedBy,
        NftablesTarget ...$alsoSupportedBy,
    )
    {
        $this->m_description = $description;
        $this->m_nftablesVersion = $nftablesVersion;
        $this->m_kernelVersion = $kernelVersion;
        $this->m_isUsedBy = $isUsedBy;
        $this->m_alsoSupportedBy = new NftablesTargetCollection(array_values($alsoSupportedBy));
    }


    /**
     * Check whether a definition uses this feature.
     *
     * @param array $definition - a table, chain, set or rule's toArray().
     *
     * @return bool
     */
    public function isUsedBy(array $definition) : bool
    {
        return ($this->m_isUsedBy)($definition);
    }


    /**
     * Check whether a target's nft has the feature.
     *
     * @param NftablesTarget $target - the target.
     *
     * @return bool
     */
    public function isInNftablesOf(NftablesTarget $target) : bool
    {
        return $target->hasNftablesAtLeast($this->m_nftablesVersion) || $this->isBackportedTo($target);
    }


    /**
     * Check whether a target's kernel has the feature.
     *
     * @param NftablesTarget $target - the target.
     *
     * @return bool
     */
    public function isInKernelOf(NftablesTarget $target) : bool
    {
        $isNewEnough = ($this->m_kernelVersion === "" || $target->hasKernelAtLeast($this->m_kernelVersion));
        return $isNewEnough || $this->isBackportedTo($target);
    }


    /**
     * Check whether a target's distribution backported the feature to its older nft or kernel.
     *
     * @param NftablesTarget $target - the target.
     *
     * @return bool
     */
    public function isBackportedTo(NftablesTarget $target) : bool
    {
        return $this->m_alsoSupportedBy->contains($target);
    }


    # Accessors
    public function getDescription() : string { return $this->m_description; }
    public function getNftablesVersion() : string { return $this->m_nftablesVersion; }
    public function getKernelVersion() : string { return $this->m_kernelVersion; }
}
