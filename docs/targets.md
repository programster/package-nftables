# Targets

- [Why a ruleset needs a target](#why-a-ruleset-needs-a-target)
- [Picking a target](#picking-a-target)
- [Features that need a newer target](#features-that-need-a-newer-target)
- [How the targets are tested](#how-the-targets-are-tested)

The examples leave out `use` statements. Every class is in `Programster\Nftables`, or one of its `Enums`,
`Statements`, `Expressions` and `Exceptions` namespaces.

## Why a ruleset needs a target
The machine that generates a ruleset often isn't the one that loads it, and the server's nft can be years older. Old
versions of nft don't just reject what they can't handle: some silently ignore it. For example, nft 1.0.9 and older
load a dormant table, but quietly drop the flag, so its rules stay on.

So a `Ruleset` is told where it will be loaded, with an `NftablesTarget`, and refuses anything that target can't load,
when it's added:

```php
$ruleset = new Ruleset(NftablesTarget::DEBIAN_12);
```

```php
// Throws UnsupportedFeatureException
// "The dormant table flag needs nft 1.1.3 or later, but this ruleset is for Debian 12 (nft 1.0.6). Pass a newer
// NftablesTarget to the Ruleset to use it."
$ruleset->addTable(new Table("staging", Family::INET, TableFlag::DORMANT));
```

Without a target, a ruleset is for the oldest supported nft (0.9.8, as in Debian 11), so it loads anywhere, and only
the features every target has can be used. That's nearly all of them: see below.

The target never changes the JSON. It's always written in a form every supported version reads (e.g. nft before 1.1
can't read a bitwise operation on more than two values, so they're always written as nested pairs).

## Picking a target
Pick the server's operating system release, as these also know its kernel, which some features need:

| Target | nft | Kernel |
|---|---|---|
| `DEBIAN_11` | 0.9.8 | 5.10 |
| `DEBIAN_12` | 1.0.6 | 6.1 |
| `DEBIAN_13` | 1.1.3 | 6.12 |
| `UBUNTU_22_04` | 1.0.2 | 5.15 |
| `UBUNTU_24_04` | 1.0.9 | 6.8 |
| `UBUNTU_26_04` | 1.1.6 | 6.8 or later |
| `ROCKY_8`, `ALMA_8`, `RHEL_8` | 1.0.4 | 4.18 |
| `ROCKY_9`, `ALMA_9`, `RHEL_9` | 1.0.9 | 5.14 |
| `ROCKY_10`, `ALMA_10`, `RHEL_10` | 1.1.5 | 6.12 |

The kernels are the oldest each release ships, e.g. Ubuntu's original kernel, not its newer HWE ones. The Rocky
Linux, AlmaLinux and RHEL targets are for an up to date release (e.g. 8.10 for 8), as each major release updates its
nft: the early 8.x releases had nft 0.9.3, which is older than this package supports.

For anything else, there's a target for each nft version that's tested: `NFTABLES_0_9_8`, `NFTABLES_1_0_2`,
`NFTABLES_1_0_4`, `NFTABLES_1_0_6`, `NFTABLES_1_0_9`, `NFTABLES_1_1_3`, `NFTABLES_1_1_5` and `NFTABLES_1_1_6`. Pick the
newest one that isn't newer than the server's (`nft --version`). These only know nft's version, so they can't catch
the features that need a newer kernel.

## Features that need a newer target
Everything not listed here works on every target, from nft 0.9.8 up.

| Feature | Needs | Because |
|---|---|---|
| `TableFlag::DORMANT` | nft 1.1.3, or Rocky/AlmaLinux/RHEL 9 | Older nft silently drops the flag, so the table's rules stay on. Red Hat backported it to RHEL 9's nft 1.0.9. |
| Chains on the ingress or egress hook | nft 1.0.6 | Older nft can't read a chain's device from JSON (0.9.8 and 1.0.4 refuse it, and 1.0.2 crashes), although its own syntax works |
| Chains on the egress hook | Kernel 5.16 as well | The kernel needs to support the hook. Rocky/AlmaLinux/RHEL 9's nft is new enough, but their kernel isn't. |
| A [flowtable](flowtables.md) | nft 1.0.6 | Older nft can't read a flowtable's devices from JSON (0.9.8 crashes, and 1.0.2 and 1.0.4 silently drop them) |
| A [named map](maps.md) whose values are concatenations (e.g. an address and port) | nft 1.1.3, or Rocky/AlmaLinux/RHEL 9 | Older nft crashes on one, or silently drops the map. Red Hat backported the fix to RHEL 9's nft 1.0.9. Two maps, one for the address and one for the port, work everywhere. |
| An [anonymous map](maps.md#anonymous-maps) whose values are concatenations | nft 1.0.2 | nft 0.9.8 can't read one from JSON |
| A [set update](statements.md#adding-to-sets-from-rules-meters) with statements (a meter) | nft 1.0.6 | Older nft silently drops the statements, leaving a plain set update |
| A [conntrack timeout](objects.md#conntrack-timeouts) | nft 1.0.9, and kernel 4.19 | nft 0.9.8 crashes on one, and 1.0.2 to 1.0.6 silently drop its timeouts |
| A [named synproxy](objects.md#synproxies) | nft 1.1.3, or Rocky/AlmaLinux/RHEL 9, and kernel 5.3 | Older nft can't read one from JSON. Red Hat backported it to RHEL 9's nft 1.0.9. |
| A [synproxy](statements.md#synproxy) | Kernel 5.3 | RHEL 8's kernel doesn't have it |
| A [transparent proxy](statements.md#transparent-proxying) | Kernel 4.19, or RHEL 8 | RHEL 8's kernel has it backported, so every target has it |
| [Operating system fingerprinting](expressions.md#operating-system-fingerprinting) | Kernel 4.19 | RHEL 8's kernel doesn't have it |
| Setting a [security mark](objects.md#security-marks) | nft 1.0.6 | Older nft can't read the statement from JSON |
| An [SCTP chunk](expressions.md#sctp-chunks) | nft 1.0.2, and kernel 5.14 or RHEL 8 | nft 0.9.8 can't read one from JSON. RHEL 8's kernel has it backported, but Debian 11's kernel doesn't have it. |

## How the targets are tested
`testing/run-all-targets.sh` runs the whole test suite on each operating system target, in a Docker container with
that release's own nft, and CI runs it on every change (see [Testing](testing.md)). Among the tests:

- every feature is loaded into each target's nft, and checked to have loaded completely, with nothing silently
  dropped.
- each feature in the table above is checked to be refused for the targets that can't load it, and (where it's nft
  that's too old) to really fail, or be dropped, when it's loaded into that nft anyway. So the table can't claim a
  limit that isn't there, or miss one that is.

AlmaLinux and RHEL ship the same nft as Rocky Linux, so the Rocky Linux containers test them. Containers share the
host's kernel, so the kernel limits come from the kernel's own history, rather than tests, and the RHEL kernels'
backports from the kernel modules in their packages.
