# Rulesets

- [Building a ruleset](#building-a-ruleset)
- [Reset modes](#reset-modes)
- [Loading it safely](#loading-it-safely)
- [What gets added for you](#what-gets-added-for-you)
  - [Empty chains](#empty-chains)
  - [Empty tables](#empty-tables)
- [Conflicts](#conflicts)
- [Output](#output)

The examples leave out `use` statements. See [namespaces](getting-started.md#namespaces) for where each class is.

## Building a ruleset
A `Ruleset` is a complete file for `nft --json --file`. Give it the rules, and it works out the rest:

```php
$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);

$rules = new RuleCollection(
    RuleFactory::createAcceptInterface($input, "lo"),
    RuleFactory::createAcceptPort($input, "eth0", new PortSet(80, 443)),
);

$ruleset = new Ruleset($rules);

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

Everything is passed to its constructor, and it can't be changed afterwards:

| Parameter | Default | Use |
|---|---|---|
| `$rules` | (required) | The rules, as a `RuleCollection`, in the order they should be matched. It can be empty. |
| `$target` | `NftablesTarget::NFTABLES_0_9_8` | The [target](targets.md) it will be loaded on, e.g. `NftablesTarget::DEBIAN_12`. Anything that target's nft can't load, or would silently ignore, throws an `UnsupportedFeatureException`. The default, the oldest supported nft, loads anywhere. |
| `$resetMode` | `RulesetResetMode::REPLACE_OWN_TABLES` | What to clear out before loading it: see [reset modes](#reset-modes) |
| `$emptyChains` | none | Base chains with no rules, kept for their policy: see [empty chains](#empty-chains) |
| `$emptyTables` | none | Tables with nothing in them: see [empty tables](#empty-tables) |

A `RuleCollection` takes its rules as arguments, e.g. `new RuleCollection($first, $second)`, and can't be changed once
it's created.

`toJson()` gives pretty printed JSON, and throws a `JsonException` rather than returning an empty string if something
can't be encoded (e.g. a comment that isn't valid UTF-8). `toArray()` gives the same thing as plain PHP arrays, and the
ruleset can also be passed straight to `json_encode()`.

## Reset modes
Loading a ruleset first clears out the old version of its rules, so reloading it never stacks up duplicates. The
constructor's reset mode (its third parameter, after the rules and the target) decides how much is cleared:

- `RulesetResetMode::REPLACE_OWN_TABLES` (the default) deletes and recreates only the tables in this ruleset. Tables
  created by other software, such as fail2ban or Docker, are left alone. This is the right choice almost all the time.
- `RulesetResetMode::FLUSH_ENTIRE_RULESET` flushes every table on the machine first, including ones this ruleset knows
  nothing about. Only use it if this ruleset should be the only thing using nftables on the machine. Anything else's
  rules (e.g. fail2ban's bans, or Docker's networking) are gone until that software adds them again.

```php
$ruleset = new Ruleset($rules, resetMode: RulesetResetMode::FLUSH_ENTIRE_RULESET);
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
A rule brings everything it uses into the ruleset:

- its chain, and the chain's table
- any chains it jumps to, or goes to (see [regular chains](tables-and-chains.md#regular-chains))
- any [named sets](sets.md) it matches against or adds to
- any [maps and verdict maps](maps.md) it looks up, and the chains a verdict map's elements jump or go to
- any [flowtable](flowtables.md) it offloads to
- any [named objects](objects.md) it uses, e.g. a named counter

A set, map, flowtable, named object or regular chain that no rule uses would do nothing, so there's no way to pass
one in: it's only ever included by a rule that uses it. That way, nothing can end up in the ruleset unused, leaving you
wondering why it has no effect.

### Empty chains
A base chain with no rules still does something: its policy applies to every packet it sees. E.g. on a machine that
mustn't route anything, a forward chain with a drop policy and no rules drops everything that would be forwarded. Pass
chains like that as `EmptyChain`s, which take the same arguments as a `BaseChain`, in an `EmptyChainCollection`, as
`$emptyChains`. An `EmptyChain` isn't a `Chain`, so no rule can be created in it. Their tables come with them:

```php
$table = new Table("firewall", Family::INET);
$forward = new EmptyChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::DROP);
$ruleset = new Ruleset(new RuleCollection(), emptyChains: new EmptyChainCollection($forward));
```

```nft
chain forward {
	type filter hook forward priority filter; policy drop;
}
```

An empty chain with the same name, in the same table, as a chain that has rules throws a `ConflictException`, as it
can't be both.

### Empty tables
A table with anything in it comes into the ruleset with its chains and other items, so it never needs passing in. The
rare table with nothing in it at all, e.g. one that's no longer used, to be emptied without deleting it, has to be
asked for explicitly, with an `EmptyTable` (a name and a family) in an `EmptyTableCollection`:

```php
$ruleset = new Ruleset($rules, emptyTables: new EmptyTableCollection(new EmptyTable("old_firewall", Family::INET)));
```

```nft
table inet old_firewall {
}
```

With `REPLACE_OWN_TABLES`, each load deletes it and recreates it empty. An empty table with the same family and name as
a table that's in use throws a `ConflictException`, as it can't be both.

Including the same item more than once only includes it once, even when they're separate objects, as long as they're the
same (e.g. built by the same code in two places). In the output, tables come first, then chains, then everything else in
the tables (sets, maps, flowtables and named objects), then rules, so nothing refers to something that doesn't exist
yet.  ## Conflicts Giving it two different things with the same name in the same place, e.g. two `input` chains in one
table with different policies, throws a `ConflictException`, rather than silently keeping one of them:

```php
// Throws ConflictException
$table = new Table("firewall", Family::INET);

$dropping = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$accepting = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);
$ruleset = new Ruleset(new RuleCollection(Rule::create($dropping, Verdict::ACCEPT), Rule::create($accepting, Verdict::ACCEPT)));
```

Sets and maps share their names in nftables, so a set and a map with the same name in one table conflict too. Each
kind of named object has names of its own, so a counter and a quota can share one.

A conflict, or anything the target can't load, throws from the constructor, so there's never a half-built ruleset.

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
