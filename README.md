Nftables Package
================

A PHP package to help generate Nftables rules in JSON form.


## Building a complete ruleset

`NftablesRuleset` puts together a whole ruleset file, ready to be loaded with `nft --json --file`. It takes care of
the parts that are easy to get wrong by hand:

* The metainfo block always comes first.
* The old rules are cleared out first, in the same file, so reloading never stacks up duplicate rules.
* Tables come before chains, and chains before rules, whatever order you add them in.

Adding a rule adds its chain and table for you, so you only need `addChain()` for a chain that has no rules (e.g. one
that exists just for its drop policy). Rules are evaluated in the order you add them.

```php
use Programster\Nftables\NftablesChain;
use Programster\Nftables\NftablesRule;
use Programster\Nftables\NftablesRuleset;
use Programster\Nftables\NftablesTable;
use Programster\Nftables\Enums\NftablesChainHook;
use Programster\Nftables\Enums\NftablesChainType;
use Programster\Nftables\Enums\NftablesFamily;
use Programster\Nftables\Enums\NftablesPolicy;
use Programster\Nftables\Enums\NftablesPriority;

$table = new NftablesTable("myFirewall", NftablesFamily::INET);

$input = new NftablesChain(
    "input",
    $table,
    NftablesChainType::FILTER,
    NftablesChainHook::INPUT,
    NftablesPriority::NF_IP_PRI_FILTER,
    NftablesPolicy::DROP,
);

$ruleset = new NftablesRuleset();
$ruleset->addRule(new NftablesRule($input, [["accept" => null]], "allow everything (for now)"));

file_put_contents("/etc/my-firewall/ruleset.json", $ruleset->toJson());
```

```bash
nft --json --file /etc/my-firewall/ruleset.json
```

Adding the same table or chain twice (even as separate objects) only includes it once. Adding a *different* chain with
the same name to the same table throws an `ExceptionChainConflict`.


### Reset modes

The constructor takes an `NftablesRulesetResetMode`, which decides what is cleared out before the new rules go in:

* `REPLACE_OWN_TABLES` (the default): deletes and recreates only the tables in this ruleset. Tables created by other
  software, such as fail2ban or Docker, are left alone. This is the right choice almost all the time.
* `FLUSH_ENTIRE_RULESET`: flushes every table on the machine first, including ones this ruleset knows nothing about.
  Only use it if this ruleset is meant to be the only thing using nftables on the machine. Anything else's rules
  (e.g. fail2ban bans or Docker's networking) are wiped until that software adds them again.

```php
$ruleset = new NftablesRuleset(NftablesRulesetResetMode::FLUSH_ENTIRE_RULESET);
```

With `REPLACE_OWN_TABLES`:

* Give your tables distinctive names. If your ruleset has an `ip nat` or `ip filter` table, it replaces the tables of
  the same name that iptables-nft (and so Docker) uses.
* A table you remove from your ruleset, or rename, isn't deleted on the next load, as the ruleset no longer mentions
  it. Delete it once by hand (`nft delete table <family> <name>`).


### Load it in one go

nft applies a single `--file` as one atomic transaction. If any part of the file fails, nothing changes and the
previous rules stay in place. That only protects you if the clear out and the new rules are in the same file, which
is what `NftablesRuleset` does for you. So:

* **Don't** run `nft flush ruleset` (or delete tables) as a separate command before loading the file. If the load
  then fails, e.g. because a PHP warning ended up in the JSON, the machine is left with no firewall at all.
* **Do** load the file with a single `nft --json --file ruleset.json`, and check its exit status.


## Running the tests

```bash
composer install
composer test                               # or: php testing/main.php
NFTABLES_TEST_ONLY="FLUSH" composer test    # only the tests whose name contains FLUSH
```

The tests are plain PHP scripts in `testing/tests/`, with no test framework needed. A test fails if it throws, fails
a check, or raises a PHP warning or deprecation. It exits with a non-zero code if anything fails.

Some tests load rulesets into real nft. They run inside a throwaway network namespace (`unshare -rn`), so they need
no root and never touch the host's rules. They're skipped, and listed as skipped, where nft or unprivileged user
namespaces aren't available.
