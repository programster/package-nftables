# Errors

Mistakes are caught where they're made, with a message that says what's wrong, rather than failing later in nft, or
worse, loading and doing the wrong thing.

| Exception | Thrown when | Extends |
|---|---|---|
| `BadArgumentException` | An argument can't be valid nftables, e.g. a port above 65535, a 200 byte rule comment, or a NAT chain on the forward hook | `InvalidArgumentException` |
| `InvalidAddressException` | A string isn't an IP address, or a network CIDR, where one is needed. For a host CIDR (e.g. 192.168.0.1/24), the message suggests the network. | `BadArgumentException` |
| `UnsuitableChainException` | A chain can't be used for something, e.g. a port forward given a filter chain, flow offloading outside the forward hook, or a jump to a chain (or use of a set, map, flowtable or named object) in another table | `BadArgumentException` |
| `ConflictException` | A ruleset is given two different tables, chains, sets, maps, flowtables or named objects with the same name in the same place | `LogicException` |
| `UnsupportedFeatureException` | A ruleset is given something its [target](targets.md)'s nft (or kernel) can't load, or would silently ignore | `LogicException` |

All of them implement the `NftablesException` interface (in `Programster\Nftables\Exceptions`), so they can be caught
together:

```php
try
{
    $range = new PortRange(6000, 5000);
}
catch (NftablesException $e)
{
    // "A port range's max port (5000) must be above its min (6000)."
    $message = $e->getMessage();
}
```

`Ruleset::toJson()` can also throw a `JsonException`, from PHP itself, if something can't be encoded (e.g. a comment
that isn't valid UTF-8).
