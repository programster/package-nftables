# Rulesets

- [Building a ruleset](#building-a-ruleset)
- [Reset modes](#reset-modes)
- [Loading it safely](#loading-it-safely)
- [What gets added for you](#what-gets-added-for-you)
- [Conflicts](#conflicts)
- [Output](#output)

The examples leave out `use` statements. Every class is in `Programster\Nftables`, or one of its `Enums`,
`Statements`, `Expressions` and `Exceptions` namespaces.

## Building a ruleset
A `Ruleset` is a complete file for `nft --json --file`. Add rules to it, and it works out the rest:

```php
$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);

$ruleset = new Ruleset();
$ruleset->addRule(RuleFactory::createAcceptInterface($input, "lo"));
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", new PortSet(80, 443)));

file_put_contents("/etc/firewall/ruleset.json", $ruleset->toJson());
```

```nft
table inet firewall {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "eth0" tcp dport { 80, 443 } accept
	}
}
```

Its constructor takes the [target](targets.md) it will be loaded on, e.g. `NftablesTarget::DEBIAN_12`, and refuses
anything that target's nft can't load, or would silently ignore, with an `UnsupportedFeatureException`. Without a
target, it's for the oldest supported nft (0.9.8), so it loads anywhere.

It's mutable, as it's built up one rule at a time. Rules are evaluated in the order they're added, so add them in the
order you want them matched. `addRule()` takes any number of rules at once.

`toJson()` gives pretty printed JSON, and throws a `JsonException` rather than returning an empty string if something
can't be encoded (e.g. a comment that isn't valid UTF-8). `toArray()` gives the same thing as plain PHP arrays, and the
ruleset can also be passed straight to `json_encode()`.

## Reset modes
Loading a ruleset first clears out the old version of its rules, so reloading it never stacks up duplicates. The
constructor's reset mode (its second parameter, after the target) decides how much is cleared:

- `RulesetResetMode::REPLACE_OWN_TABLES` (the default) deletes and recreates only the tables in this ruleset. Tables
  created by other software, such as fail2ban or Docker, are left alone. This is the right choice almost all the time.
- `RulesetResetMode::FLUSH_ENTIRE_RULESET` flushes every table on the machine first, including ones this ruleset knows
  nothing about. Only use it if this ruleset should be the only thing using nftables on the machine. Anything else's
  rules (e.g. fail2ban's bans, or Docker's networking) are gone until that software adds them again.

```php
$ruleset = new Ruleset(resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
```

With `REPLACE_OWN_TABLES`:

- **Give your tables distinctive names.** A table called `ip nat` or `ip filter` would replace the tables of the same
  name that iptables-nft (and so Docker) uses.
- **A table you stop using isn't deleted.** If you remove a table from your ruleset, or rename it, the next load
  doesn't mention it, so it's left as it was. Delete it once by hand: `nft delete table <family> <name>`.
- **Sets are recreated too.** Elements added to a [named set](sets.md) at runtime (e.g. with `nft add element`) are
  lost when the ruleset is reloaded, as the set is recreated with only the elements in the ruleset.

## Loading it safely
nft applies a single `--file` as one atomic transaction: if any part of it fails, nothing changes and the rules that
were already loaded stay in place. Because the clear out is inside the same file, a ruleset that fails to load can't
leave the machine with no firewall. That only holds if it's loaded in one go:

- **Don't** run `nft flush ruleset` (or delete tables) as a separate command first. If the load then fails, e.g.
  because a PHP warning ended up in the JSON, the machine is left with no firewall at all.
- **Do** load it with a single `nft --json --file ruleset.json`, and check its exit status.

To check a file without loading it, add `--check` (`-c`): `nft --check --json --file ruleset.json`.

## What gets added for you
Adding a rule adds everything it uses:

- its chain, and the chain's table
- any chains it jumps to, or goes to (see [regular chains](tables-and-chains.md#regular-chains))
- any [named sets](sets.md) it matches against or adds to
- any [maps and verdict maps](maps.md) it looks up, and the chains a verdict map's elements jump or go to
- any [flowtable](flowtables.md) it offloads to
- any [named objects](objects.md) it uses, e.g. a named counter

So only the items that no rule uses need adding explicitly, with `addChain()`, `addSet()`, `addMap()`,
`addFlowtable()` or `addObject()`, e.g. a chain that exists just for its drop policy. `addTable()` does the same for
an empty table.

Adding the same item more than once only includes it once, even when they're separate objects, as long as they're the
same (e.g. built by the same code in two places). In the output, tables come first, then chains, then everything else
in the tables (sets, maps, flowtables and named objects), then rules, so nothing refers to something that doesn't
exist yet.

## Conflicts
Adding something different with the same name in the same place, e.g. two `input` chains in one table with different
policies, throws a `ConflictException`, rather than silently keeping one of them:

```php
// Throws ConflictException
$table = new Table("firewall", Family::INET);
$ruleset = new Ruleset();
$ruleset->addChain(new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP));
$ruleset->addChain(new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT));
```

Sets and maps share their names in nftables, so a set and a map with the same name in one table conflict too. Each
kind of named object has names of its own, so a counter and a quota can share one.

When `addRule()` is given several rules and any of them conflicts, none of them are added.

## Output
The first item is always a metainfo block, which tells nft the JSON schema version the file uses. With
`REPLACE_OWN_TABLES`, each table is then added (so deleting it can't fail if it doesn't exist yet, e.g. on first boot)
and deleted, before everything is defined again:

```json
{
    "nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"add": {"table": {"family": "inet", "name": "firewall"}}},
        {"delete": {"table": {"family": "inet", "name": "firewall"}}},
        {"table": {"family": "inet", "name": "firewall"}},
        {"chain": {"family": "inet", "table": "firewall", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}
    ]
}
```
