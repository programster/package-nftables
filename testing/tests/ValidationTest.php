<?php

/*
 * Tests that invalid or dangerous input is caught when it's created, with a message that says why, rather than
 * failing later in nft (or worse, loading and doing the wrong thing). Also covers the bugs fixed in 1.0.0. These are
 * run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\AnonymousMap;
use Programster\Nftables\AnonymousVerdictMap;
use Programster\Nftables\BaseChain;
use Programster\Nftables\Collections\PortForwardCollection;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\BinaryOperator;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\CtHelperType;
use Programster\Nftables\Enums\CtTimeoutState;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\FibFlag;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Enums\IpsecDirection;
use Programster\Nftables\Enums\IpsecKey;
use Programster\Nftables\Enums\Ipv6ExtensionHeaderField;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\LimitMatch;
use Programster\Nftables\Enums\LimitPeriod;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\NumgenMode;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\PayloadBase;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\PortForwardMapLayout;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\QueueFailMode;
use Programster\Nftables\Enums\QuotaMatch;
use Programster\Nftables\Enums\QuotaUnit;
use Programster\Nftables\Enums\SctpChunk;
use Programster\Nftables\Enums\SctpChunkField;
use Programster\Nftables\Enums\SetFlag;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\SetUpdateOperation;
use Programster\Nftables\Enums\TcpOptionField;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\Expressions\BinaryOperationExpression;
use Programster\Nftables\Expressions\ConcatExpression;
use Programster\Nftables\Expressions\ExthdrExpression;
use Programster\Nftables\Expressions\FibExpression;
use Programster\Nftables\Expressions\HashExpression;
use Programster\Nftables\Expressions\IpsecExpression;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\NumgenExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Expressions\PrefixExpression;
use Programster\Nftables\Expressions\SctpChunkExpression;
use Programster\Nftables\Expressions\SetExpression;
use Programster\Nftables\Expressions\TcpOptionExpression;
use Programster\Nftables\Expressions\TimedElement;
use Programster\Nftables\Flowtable;
use Programster\Nftables\MapElement;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\NamedMap;
use Programster\Nftables\NamedSet;
use Programster\Nftables\NamedVerdictMap;
use Programster\Nftables\NetworkLib;
use Programster\Nftables\Objects\CtExpectation;
use Programster\Nftables\Objects\CtHelper;
use Programster\Nftables\Objects\CtTimeout;
use Programster\Nftables\Objects\CtTimeoutPolicy;
use Programster\Nftables\Objects\NamedCounter;
use Programster\Nftables\Objects\NamedSynproxy;
use Programster\Nftables\Objects\Secmark;
use Programster\Nftables\PortForward;
use Programster\Nftables\PortRange;
use Programster\Nftables\PortSet;
use Programster\Nftables\RegularChain;
use Programster\Nftables\Rule;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Statements\ConnectionLimitStatement;
use Programster\Nftables\Statements\CounterStatement;
use Programster\Nftables\Statements\DupStatement;
use Programster\Nftables\Statements\FlowOffloadStatement;
use Programster\Nftables\Statements\FwdStatement;
use Programster\Nftables\Statements\JumpStatement;
use Programster\Nftables\Statements\LimitStatement;
use Programster\Nftables\Statements\LogStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\MatchStatement;
use Programster\Nftables\Statements\QueueStatement;
use Programster\Nftables\Statements\QuotaStatement;
use Programster\Nftables\Statements\SetUpdateStatement;
use Programster\Nftables\Statements\SynproxyStatement;
use Programster\Nftables\Statements\TproxyStatement;
use Programster\Nftables\Table;
use Programster\Nftables\VerdictMapElement;
use Programster\Nftables\Testing\Fixtures;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */

$ipTable = Fixtures::createTable("t");
$input = Fixtures::createInputChain($ipTable);

// Each case is a description, the exception it should throw, text its message should contain, and the code that
// should throw it.
$cases = [];

# Ports, addresses and states

$createAPortOf0 = function () : void {
    new PortSet(0);
};

$cases[] = ["a port of 0", BadArgumentException::class, "between 1 and 65535", $createAPortOf0];

$createAPortAbove65535 = function () : void {
    MatchFactory::createDestinationPorts(Protocol::TCP, 65536);
};

$cases[] = ["a port above 65535", BadArgumentException::class, "between 1 and 65535", $createAPortAbove65535];

$createAnEmptyPortSet = function () : void {
    new PortSet();
};

$cases[] = ["an empty port set", BadArgumentException::class, "at least one port", $createAnEmptyPortSet];

$createAPortRangeOfOnePort = function () : void {
    new PortRange(80, 80);
};

$cases[] = ["a port range of one port", BadArgumentException::class, "must be above", $createAPortRangeOfOnePort];

$createAPortRangeOutOfRange = function () : void {
    new PortRange(0, 70000);
};

$cases[] = [
    "a port range out of range",
    BadArgumentException::class,
    "between 1 and 65535",
    $createAPortRangeOutOfRange,
];

$createAnEmptyConnectionStateSet = function () : void {
    new ConnectionStateSet();
};

$cases[] = [
    "an empty connection state set",
    BadArgumentException::class,
    "at least one state",
    $createAnEmptyConnectionStateSet,
];

$createAHostCIDRSuggestingTheNetwork = function () : void {
    MatchFactory::createSourceAddress("192.168.0.1/24");
};

$cases[] = [
    "a host CIDR, suggesting the network",
    InvalidAddressException::class,
    "192.168.0.0/24",
    $createAHostCIDRSuggestingTheNetwork,
];

$createSomethingThatIsnTAnAddress = function () : void {
    MatchFactory::createDestinationAddress("example.com");
};

$cases[] = [
    "something that isn't an address",
    InvalidAddressException::class,
    "isn't an IP address",
    $createSomethingThatIsnTAnAddress,
];

$createAnInvalidPrefixLength = function () : void {
    new PrefixExpression("10.0.0.0", 33);
};

$cases[] = [
    "an invalid prefix length",
    InvalidAddressException::class,
    "isn't a valid CIDR",
    $createAnInvalidPrefixLength,
];

# Names, chains and rules

$createAnEmptyTableName = function () : void {
    new Table("", Family::IP);
};

$cases[] = ["an empty table name", BadArgumentException::class, "table name", $createAnEmptyTableName];

$createA256ByteChainName = function () use ($ipTable) : void {
    new RegularChain(str_repeat("x", 256), $ipTable);
};

$cases[] = ["a 256 byte chain name", BadArgumentException::class, "chain name", $createA256ByteChainName];

$createANatChainInTheArpFamily = function () : void {
    $arp = new Table("a", Family::ARP);
    new BaseChain("c", $arp, ChainType::NAT, ChainHook::INPUT, 0, Policy::ACCEPT);
};

$cases[] = ["a nat chain in the arp family", BadArgumentException::class, "nat chain", $createANatChainInTheArpFamily];

$createANatChainOnTheForwardHook = function () use ($ipTable) : void {
    new BaseChain("c", $ipTable, ChainType::NAT, ChainHook::FORWARD, 0, Policy::ACCEPT);
};

$cases[] = [
    "a nat chain on the forward hook",
    BadArgumentException::class,
    "forward hook",
    $createANatChainOnTheForwardHook,
];

$createARouteChainOnTheInputHook = function () use ($ipTable) : void {
    new BaseChain("c", $ipTable, ChainType::ROUTE, ChainHook::INPUT, 0, Policy::ACCEPT);
};

$cases[] = [
    "a route chain on the input hook",
    BadArgumentException::class,
    "route chain",
    $createARouteChainOnTheInputHook,
];

$createAHookTheFamilyDoesnTHave = function () : void {
    $arp = new Table("a", Family::ARP);
    new BaseChain("c", $arp, ChainType::FILTER, ChainHook::PREROUTING, 0, Policy::ACCEPT);
};

$cases[] = [
    "a hook the family doesn't have",
    BadArgumentException::class,
    "no prerouting hook",
    $createAHookTheFamilyDoesnTHave,
];

$createAnIngressChainWithNoDevice = function () : void {
    $netdev = new Table("n", Family::NETDEV);
    new BaseChain("c", $netdev, ChainType::FILTER, ChainHook::INGRESS, 0, Policy::ACCEPT);
};

$cases[] = [
    "an ingress chain with no device",
    BadArgumentException::class,
    "needs a device",
    $createAnIngressChainWithNoDevice,
];

$createADeviceOnAnInputChain = function () use ($ipTable) : void {
    new BaseChain("c", $ipTable, ChainType::FILTER, ChainHook::INPUT, 0, Policy::ACCEPT, "eth0");
};

$cases[] = [
    "a device on an input chain",
    BadArgumentException::class,
    "ingress and egress",
    $createADeviceOnAnInputChain,
];

$createAPriorityTheFamilyDoesnTHave = function () : void {
    $bridge = new Table("b", Family::BRIDGE);
    new BaseChain("c", $bridge, ChainType::FILTER, ChainHook::INPUT, Priority::RAW, Policy::ACCEPT);
};

$cases[] = [
    "a priority the family doesn't have",
    BadArgumentException::class,
    "RAW priority",
    $createAPriorityTheFamilyDoesnTHave,
];

$createARuleWithNoStatements = function () use ($input) : void {
    Rule::create($input, );
};

$cases[] = [
    "a rule with no statements",
    BadArgumentException::class,
    "at least one statement",
    $createARuleWithNoStatements,
];

$createARuleWithSomethingThatIsnTAStatement = function () use ($input) : void {
    Rule::create($input, ["accept" => null]);
};

// Caught by PHP itself, as the statements are a typed variadic.
$cases[] = [
    "a rule with something that isn't a statement",
    TypeError::class,
    "must be of type Programster\\Nftables\\Statements\\Statement",
    $createARuleWithSomethingThatIsnTAStatement,
];

$createA129ByteRuleComment = function () use ($input) : void {
    Rule::create($input, Verdict::ACCEPT)->withComment(str_repeat("x", 129));
};

$cases[] = ["a 129 byte rule comment", BadArgumentException::class, "128 bytes", $createA129ByteRuleComment];

$createAJumpToAnotherTable = function () use ($input) : void {
    $other = new RegularChain("c", new Table("other", Family::IP));
    Rule::create($input, new JumpStatement($other));
};

$cases[] = ["a jump to another table", UnsuitableChainException::class, "another table", $createAJumpToAnotherTable];

$createASetFromAnotherTable = function () use ($input) : void {
    $set = NamedSet::createAddressSet(new Table("other", Family::IP), "s", IpVersion::IPV4);
    Rule::create($input, MatchFactory::createInSet(PayloadExpression::create(PayloadField::IP_SADDR), $set));
};

$cases[] = ["a set from another table", UnsuitableChainException::class, "another table", $createASetFromAnotherTable];

# Statements and expressions

$createAStringThatWouldBecomeASetReference = function () : void {
    new MatchStatement(PayloadExpression::create(PayloadField::IP_SADDR), Operator::EQUALS, "@blocklist");
};

$cases[] = [
    "a string that would become a set reference",
    BadArgumentException::class,
    "set reference",
    $createAStringThatWouldBecomeASetReference,
];

$createAnEmptyAnonymousSet = function () : void {
    new SetExpression();
};

$cases[] = ["an empty anonymous set", BadArgumentException::class, "at least one element", $createAnEmptyAnonymousSet];

$createAConcatenationOfOneValue = function () : void {
    new ConcatExpression("10.0.0.1");
};

$cases[] = [
    "a concatenation of one value",
    BadArgumentException::class,
    "at least two",
    $createAConcatenationOfOneValue,
];

$createABinaryOperationOnOneValue = function () : void {
    new BinaryOperationExpression(BinaryOperator::AND, 1);
};

$cases[] = [
    "a binary operation on one value",
    BadArgumentException::class,
    "at least two",
    $createABinaryOperationOnOneValue,
];

$createARawPayloadWithNoLength = function () : void {
    PayloadExpression::createRaw(PayloadBase::TRANSPORT_LAYER, 0, 0);
};

$cases[] = [
    "a raw payload with no length",
    BadArgumentException::class,
    "length of at least 1",
    $createARawPayloadWithNoLength,
];

$createA128ByteLogPrefix = function () : void {
    new LogStatement(str_repeat("x", 128));
};

$cases[] = ["a 128 byte log prefix", BadArgumentException::class, "127 bytes", $createA128ByteLogPrefix];

$createALimitOf0 = function () : void {
    new LimitStatement(0, LimitPeriod::SECOND, LimitMatch::OVER_LIMIT);
};

$cases[] = ["a limit of 0", BadArgumentException::class, "rate of at least 1", $createALimitOf0];

$createAQueueRangeTheWrongWayRound = function () : void {
    QueueStatement::createSpread(QueueFailMode::DROP, 5, 2);
};

$cases[] = [
    "a queue range the wrong way round",
    BadArgumentException::class,
    "can't be above",
    $createAQueueRangeTheWrongWayRound,
];

$createAMarkAbove32Bits = function () : void {
    MangleStatement::createSetMetaMark(0x100000000);
};

$cases[] = ["a mark above 32 bits", BadArgumentException::class, "0xFFFFFFFF", $createAMarkAbove32Bits];

# Named sets

$createAPrefixInASetWithoutINTERVAL = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withElements(PrefixExpression::createFromCidr("10.0.0.0/8"));
};

$cases[] = [
    "a prefix in a set without INTERVAL",
    BadArgumentException::class,
    "INTERVAL",
    $createAPrefixInASetWithoutINTERVAL,
];

$createANegativeSetTimeout = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withTimeout(-1);
};

$cases[] = ["a negative set timeout", BadArgumentException::class, "can't be negative", $createANegativeSetTimeout];

$createASetTypeThatIsnTASetType = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", new SetTypeCollection(["ipv4_addr"]));
};

// Caught by the collection, as it's built.
$cases[] = [
    "a set type that isn't a SetType",
    Ramsey\Collection\Exception\InvalidArgumentException::class,
    "must be of type Programster\\Nftables\\Enums\\SetType",
    $createASetTypeThatIsnTASetType,
];

$createAnIPv6AddressInAnIPv4Set = function () use ($ipTable) : void {
    NamedSet::createAddressSet($ipTable, "s", IpVersion::IPV4, "fd00::1");
};

$cases[] = [
    "an IPv6 address in an IPv4 set",
    InvalidAddressException::class,
    "isn't an IPV4",
    $createAnIPv6AddressInAnIPv4Set,
];

# Existence checks

$createAFibLookupWithBothAddresses = function () : void {
    new FibExpression(FibResult::OIF, FibFlag::SADDR, FibFlag::DADDR);
};

$cases[] = [
    "a fib lookup with both addresses",
    BadArgumentException::class,
    "exactly one of SADDR and DADDR",
    $createAFibLookupWithBothAddresses,
];

$createAFibLookupWithNoAddress = function () : void {
    new FibExpression(FibResult::OIF, FibFlag::IIF);
};

$cases[] = [
    "a fib lookup with no address",
    BadArgumentException::class,
    "exactly one of SADDR and DADDR",
    $createAFibLookupWithNoAddress,
];

$createAFibLookupWithBothInterfaces = function () : void {
    new FibExpression(FibResult::OIF, FibFlag::SADDR, FibFlag::IIF, FibFlag::OIF);
};

$cases[] = [
    "a fib lookup with both interfaces",
    BadArgumentException::class,
    "at most one of IIF and OIF",
    $createAFibLookupWithBothInterfaces,
];

$checkAFibTypeExists = function () : void {
    MatchFactory::createExistence(new FibExpression(FibResult::TYPE, FibFlag::DADDR), Existence::EXISTS);
};

$cases[] = [
    "checking a fib address type exists",
    BadArgumentException::class,
    "can be checked for.",
    $checkAFibTypeExists,
];

$checkAFieldExists = function () : void {
    $size = TcpOptionExpression::createField(TcpOptionField::MAXSEG_SIZE);
    MatchFactory::createExistence($size, Existence::EXISTS);
};

$cases[] = [
    "checking a TCP option field exists",
    BadArgumentException::class,
    "can be checked for.",
    $checkAFieldExists,
];

$checkAHeaderFieldExists = function () : void {
    $moreFragments = ExthdrExpression::createField(Ipv6ExtensionHeaderField::FRAG_MORE_FRAGMENTS);
    MatchFactory::createExistence($moreFragments, Existence::MISSING);
};

$cases[] = [
    "checking a header field exists",
    BadArgumentException::class,
    "can be checked for.",
    $checkAHeaderFieldExists,
];

$filterReversePathInABridge = function () : void {
    $bridge = new Table("b", Family::BRIDGE);
    RuleFactory::createReversePathFilter(Fixtures::createBaseChain($bridge, ChainType::FILTER, ChainHook::PREROUTING));
};

$cases[] = [
    "a reverse path filter in a bridge table",
    UnsuitableChainException::class,
    "ip, ip6 or inet",
    $filterReversePathInABridge,
];

$clampTheMssInAnInputChain = function () use ($input) : void {
    RuleFactory::createMssClamp($input);
};

$cases[] = [
    "MSS clamping in an input chain",
    UnsuitableChainException::class,
    "forward hook",
    $clampTheMssInAnInputChain,
];

# RuleFactory

$createAcceptingAPortInAForwardChain = function () use ($ipTable) : void {
    $forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
    RuleFactory::createAcceptPort($forward, "eth0", 22);
};

$cases[] = [
    "accepting a port in a forward chain",
    UnsuitableChainException::class,
    "input hook",
    $createAcceptingAPortInAForwardChain,
];

$createPortForwardingInAFilterChain = function () use ($input) : void {
    RuleFactory::createPortForward($input, "eth0", 80, "10.0.0.1");
};

$cases[] = [
    "port forwarding in a filter chain",
    UnsuitableChainException::class,
    "nat chain",
    $createPortForwardingInAFilterChain,
];

$createForwardingARangeToADifferentRange = function () use ($ipTable) : void {
    $prerouting = Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::PREROUTING);
    $incoming = new PortRange(5000, 6000);
    RuleFactory::createPortForward($prerouting, "eth0", $incoming, "10.0.0.1", new PortRange(7000, 8000));
};

$cases[] = [
    "forwarding a range to a different range",
    BadArgumentException::class,
    "same range",
    $createForwardingARangeToADifferentRange,
];

$createForwardingOnePortToARange = function () use ($ipTable) : void {
    $prerouting = Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::PREROUTING);
    RuleFactory::createPortForward($prerouting, "eth0", 80, "10.0.0.1", new PortRange(7000, 8000));
};

$cases[] = [
    "forwarding one port to a range",
    BadArgumentException::class,
    "same range",
    $createForwardingOnePortToARange,
];

$createASYNCheckOnUDP = function () use ($ipTable) : void {
    $forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
    RuleFactory::createForward($forward, "eth0", "eth1", protocol: Protocol::UDP, requireTcpSyn: true);
};

$cases[] = ["a SYN check on UDP", BadArgumentException::class, "Only TCP", $createASYNCheckOnUDP];

$createMasqueradingInAPreroutingChain = function () use ($ipTable) : void {
    RuleFactory::createMasquerade(Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::PREROUTING), "eth0");
};

$cases[] = [
    "masquerading in a prerouting chain",
    UnsuitableChainException::class,
    "postrouting hook",
    $createMasqueradingInAPreroutingChain,
];

# Maps, flowtables and named objects

$dport = PayloadExpression::create(PayloadField::TCP_DPORT);
$saddr = PayloadExpression::create(PayloadField::IP_SADDR);
$otherTable = new Table("other", Family::IP);
$forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
$prerouting = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::PREROUTING);

$createAMapRangeWithoutIntervals = function () use ($ipTable) : void {
    $map = NamedMap::create($ipTable, "m", SetType::INET_SERVICE, SetType::IPV4_ADDR);
    $map->withElements(new MapElement(new PortRange(1, 10), "10.0.0.1"));
};

$cases[] = ["a map range without INTERVAL", BadArgumentException::class, "INTERVAL", $createAMapRangeWithoutIntervals];

$createAVerdictMapJumpToAnotherTable = function () use ($ipTable, $otherTable) : void {
    $jump = new JumpStatement(new RegularChain("c", $otherTable));
    NamedVerdictMap::create($ipTable, "m", SetType::INET_SERVICE)->withElements(new VerdictMapElement(22, $jump));
};

$cases[] = [
    "a verdict map jump to another table",
    UnsuitableChainException::class,
    "another table",
    $createAVerdictMapJumpToAnotherTable,
];

$createAnAnonymousVerdictMapJumpToAnotherTable = function () use ($input, $otherTable, $dport) : void {
    $jump = new JumpStatement(new RegularChain("c", $otherTable));
    Rule::create($input, (new AnonymousVerdictMap(new VerdictMapElement(22, $jump)))->lookUp($dport));
};

$cases[] = [
    "an anonymous verdict map jump to another table",
    UnsuitableChainException::class,
    "another table",
    $createAnAnonymousVerdictMapJumpToAnotherTable,
];

$createAMapFromAnotherTable = function () use ($input, $otherTable, $saddr) : void {
    $map = NamedMap::create($otherTable, "marks", SetType::IPV4_ADDR, SetType::MARK);
    Rule::create($input, new MangleStatement(new MetaExpression(MetaKey::MARK), $map->lookUp($saddr)));
};

$cases[] = ["a map from another table", UnsuitableChainException::class, "map marks", $createAMapFromAnotherTable];

$createAnEmptyAnonymousMap = function () : void {
    new AnonymousMap();
};

$cases[] = ["an empty anonymous map", BadArgumentException::class, "at least one element", $createAnEmptyAnonymousMap];

$createAMapValueThatWouldBecomeASetReference = function () : void {
    new MapElement(22, "@other");
};

$cases[] = [
    "a map value that would become a set reference",
    BadArgumentException::class,
    "set reference",
    $createAMapValueThatWouldBecomeASetReference,
];

$createAFlowtableWithoutDevices = function () use ($ipTable) : void {
    new Flowtable("f", $ipTable, Priority::FILTER);
};

$cases[] = ["a flowtable with no devices", BadArgumentException::class, "one device", $createAFlowtableWithoutDevices];

$createAFlowtableInABridgeTable = function () : void {
    new Flowtable("f", new Table("b", Family::BRIDGE), 0, "eth0");
};

$cases[] = ["a bridge flowtable", BadArgumentException::class, "ip, ip6 or inet", $createAFlowtableInABridgeTable];

$createAFlowtableWithALongDeviceName = function () use ($ipTable) : void {
    new Flowtable("f", $ipTable, 0, "a-sixteen-bytes!");
};

$cases[] = ["a 16 byte device name", BadArgumentException::class, "15 bytes", $createAFlowtableWithALongDeviceName];

$createAFlowOffloadInAnInputChain = function () use ($input, $ipTable) : void {
    RuleFactory::createFlowOffload($input, new Flowtable("f", $ipTable, 0, "eth0"));
};

$cases[] = [
    "flow offloading in an input chain",
    UnsuitableChainException::class,
    "forward hook",
    $createAFlowOffloadInAnInputChain,
];

$createAFlowOffloadToAnotherTable = function () use ($forward, $otherTable) : void {
    Rule::create($forward, new FlowOffloadStatement(new Flowtable("f", $otherTable, 0, "eth0")));
};

$cases[] = [
    "flow offloading to another table",
    UnsuitableChainException::class,
    "flowtable f",
    $createAFlowOffloadToAnotherTable,
];

$createAnEmptyQuota = function () : void {
    new QuotaStatement(0, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA);
};

$cases[] = ["a quota of 0", BadArgumentException::class, "at least 1", $createAnEmptyQuota];

$createANamedObjectWithoutAName = function () use ($ipTable) : void {
    new NamedCounter("", $ipTable);
};

$cases[] = ["an unnamed object", BadArgumentException::class, "name must be", $createANamedObjectWithoutAName];

$createACtHelperInABridgeTable = function () : void {
    new CtHelper("ftp", new Table("b", Family::BRIDGE), CtHelperType::FTP);
};

$cases[] = ["a bridge ct helper", BadArgumentException::class, "ip, ip6 or inet", $createACtHelperInABridgeTable];

$createACtTimeoutForTwoProtocols = function () use ($ipTable) : void {
    $tcp = new CtTimeoutPolicy(CtTimeoutState::TCP_ESTABLISHED, 60);
    new CtTimeout("t", $ipTable, $tcp, new CtTimeoutPolicy(CtTimeoutState::UDP_REPLIED, 60));
};

$cases[] = [
    "a ct timeout for two protocols",
    BadArgumentException::class,
    "exactly one protocol",
    $createACtTimeoutForTwoProtocols,
];

$createACtTimeoutWithoutPolicies = function () use ($ipTable) : void {
    new CtTimeout("t", $ipTable);
};

$cases[] = [
    "a ct timeout without timeouts",
    BadArgumentException::class,
    "exactly one protocol",
    $createACtTimeoutWithoutPolicies,
];

$createACtTimeoutWithAStateTwice = function () use ($ipTable) : void {
    $policy = new CtTimeoutPolicy(CtTimeoutState::TCP_CLOSE, 60);
    new CtTimeout("t", $ipTable, $policy, $policy);
};

$cases[] = [
    "a ct timeout with a state twice",
    BadArgumentException::class,
    "one timeout for each state",
    $createACtTimeoutWithAStateTwice,
];

$createAZeroCtTimeout = function () : void {
    new CtTimeoutPolicy(CtTimeoutState::TCP_CLOSE, 0);
};

$cases[] = ["a ct timeout of 0 seconds", BadArgumentException::class, "at least 1 second", $createAZeroCtTimeout];

$createASecmarkWithoutAContext = function () use ($ipTable) : void {
    new Secmark("s", $ipTable, "");
};

$cases[] = ["a security mark with no context", BadArgumentException::class, "context", $createASecmarkWithoutAContext];

# Synproxies, transparent proxies, set updates, numgen, hashes and SCTP chunks

$createAWindowScaleOf15 = function () : void {
    new SynproxyStatement(1460, 15);
};

$cases[] = ["a window scale of 15", BadArgumentException::class, "from 0 to 14", $createAWindowScaleOf15];

$createAMaximumSegmentSizeOf0 = function () : void {
    new SynproxyStatement(0, 7);
};

$cases[] = ["a maximum segment size of 0", BadArgumentException::class, "segment size", $createAMaximumSegmentSizeOf0];

$createASynproxyInAPreroutingChain = function () use ($prerouting) : void {
    Rule::create($prerouting, new SynproxyStatement(1460, 7));
};

$cases[] = [
    "a synproxy in a prerouting chain",
    UnsuitableChainException::class,
    "input or forward hook",
    $createASynproxyInAPreroutingChain,
];

$createANamedSynproxyInAPreroutingChain = function () use ($prerouting, $ipTable) : void {
    Rule::create($prerouting, (new NamedSynproxy("s", $ipTable, new SynproxyStatement(1460, 7)))->createStatement());
};

$cases[] = [
    "a named synproxy in a prerouting chain",
    UnsuitableChainException::class,
    "input or forward hook",
    $createANamedSynproxyInAPreroutingChain,
];

$createATproxyInAnInputChain = function () use ($input) : void {
    Rule::create($input, TproxyStatement::createToPort(IpVersion::IPV4, 3128));
};

$cases[] = [
    "a transparent proxy in an input chain",
    UnsuitableChainException::class,
    "prerouting hook",
    $createATproxyInAnInputChain,
];

$createAnIpv6TproxyInAnIpTable = function () use ($prerouting) : void {
    Rule::create($prerouting, TproxyStatement::createToAddress("::1", 3128));
};

$cases[] = [
    "an IPv6 transparent proxy in an ip table",
    UnsuitableChainException::class,
    "needs an ip6 or inet table, not ip",
    $createAnIpv6TproxyInAnIpTable,
];

$createATproxyToANetwork = function () : void {
    TproxyStatement::createToAddress("10.0.0.0/8");
};

$cases[] = ["a transparent proxy to a network", InvalidAddressException::class, "CIDR", $createATproxyToANetwork];

$createATproxyToPort0 = function () : void {
    TproxyStatement::createToPort(IpVersion::IPV4, 0);
};

$cases[] = ["a transparent proxy to port 0", BadArgumentException::class, "65535", $createATproxyToPort0];

$createASetUpdateWithoutASize = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withTimeout(60);
    new SetUpdateStatement(SetUpdateOperation::ADD, $set, $saddr);
};

$cases[] = ["a set update with no set size", BadArgumentException::class, "withSize", $createASetUpdateWithoutASize];

$createASetUpdateWithoutATimeout = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withSize(10);
    new SetUpdateStatement(SetUpdateOperation::UPDATE, $set, $saddr);
};

$cases[] = [
    "a set update to a set with no timeout",
    BadArgumentException::class,
    "withTimeout",
    $createASetUpdateWithoutATimeout,
];

$createASetDeleteWithStatements = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR);
    new SetUpdateStatement(SetUpdateOperation::DELETE, $set, $saddr, new CounterStatement());
};

$cases[] = [
    "a set delete with statements",
    BadArgumentException::class,
    "can't apply statements",
    $createASetDeleteWithStatements,
];

$createASetOfSize0 = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withSize(0);
};

$cases[] = ["a set of size 0", BadArgumentException::class, "at least 1", $createASetOfSize0];

$createASetWithMoreElementsThanItsSize = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withSize(1)->withElements("10.0.0.1", "10.0.0.2");
};

$cases[] = [
    "a set with more elements than its size",
    BadArgumentException::class,
    "more elements than its size",
    $createASetWithMoreElementsThanItsSize,
];

$createANumgenModulusOf0 = function () : void {
    new NumgenExpression(NumgenMode::INCREMENTAL, 0);
};

$cases[] = ["a numgen modulus of 0", BadArgumentException::class, "modulus", $createANumgenModulusOf0];

$createANumgenPast32Bits = function () : void {
    new NumgenExpression(NumgenMode::RANDOM, 2, 0xFFFFFFFF);
};

$cases[] = ["a numgen past 32 bits", BadArgumentException::class, "32 bits", $createANumgenPast32Bits];

$createANegativeHashSeed = function () use ($saddr) : void {
    HashExpression::createJhash($saddr, 2, 0, -1);
};

$cases[] = ["a negative hash seed", BadArgumentException::class, "seed", $createANegativeHashSeed];

$createAnSctpFieldOfTheWrongChunk = function () : void {
    SctpChunkExpression::createField(SctpChunk::INIT, SctpChunkField::TSN);
};

$cases[] = [
    "an SCTP field of the wrong chunk",
    BadArgumentException::class,
    "no tsn field",
    $createAnSctpFieldOfTheWrongChunk,
];

$checkAnSctpFieldExists = function () : void {
    $field = SctpChunkExpression::createField(SctpChunk::DATA, SctpChunkField::TSN);
    MatchFactory::createExistence($field, Existence::EXISTS);
};

$cases[] = ["an SCTP field existence check", BadArgumentException::class, "checked for.", $checkAnSctpFieldExists];

# Port forwards from a map

$natPrerouting = Fixtures::createBaseChain($ipTable, ChainType::NAT, ChainHook::PREROUTING);
$twoMaps = PortForwardMapLayout::TWO_MAPS;
$oneForward = new PortForwardCollection([new PortForward(2222, "10.0.0.2", 22)]);

$createAMapPortForwardInAFilterChain = function () use ($prerouting, $oneForward) : void {
    $layout = PortForwardMapLayout::TWO_MAPS;
    RuleFactory::createMapPortForward($prerouting, "eth0", "f", $layout, IpVersion::IPV4, $oneForward);
};

$cases[] = [
    "a map port forward in a filter chain",
    UnsuitableChainException::class,
    "a nat chain",
    $createAMapPortForwardInAFilterChain,
];

$createAnIpv6MapPortForwardInAnIpTable = function () use ($natPrerouting, $twoMaps) : void {
    $forwards = new PortForwardCollection([new PortForward(80, "fd00::1", 80)]);
    RuleFactory::createMapPortForward($natPrerouting, "eth0", "f", $twoMaps, IpVersion::IPV6, $forwards);
};

$cases[] = [
    "an IPv6 map port forward in an ip table",
    UnsuitableChainException::class,
    "needs an ip6 or inet table, not ip",
    $createAnIpv6MapPortForwardInAnIpTable,
];

$createAMixedMapPortForward = function () use ($natPrerouting, $twoMaps) : void {
    $forwards = new PortForwardCollection([new PortForward(80, "10.0.0.1", 80), new PortForward(81, "fd00::1", 80)]);
    RuleFactory::createMapPortForward($natPrerouting, "eth0", "f", $twoMaps, IpVersion::IPV4, $forwards);
};

$cases[] = ["a map port forward to both IP versions", BadArgumentException::class, "81", $createAMixedMapPortForward];

$createAPortForwardedTwice = function () use ($natPrerouting) : void {
    $forwards = new PortForwardCollection([new PortForward(80, "10.0.0.1", 80), new PortForward(80, "10.0.0.2", 80)]);
    $oneMap = PortForwardMapLayout::ONE_MAP;
    RuleFactory::createMapPortForward($natPrerouting, "eth0", "f", $oneMap, IpVersion::IPV4, $forwards);
};

$cases[] = ["a port forwarded twice", BadArgumentException::class, "more than once", $createAPortForwardedTwice];

$createAPortForwardToANetwork = function () : void {
    new PortForward(80, "10.0.0.0/8", 80);
};

$cases[] = ["a port forward to a network", InvalidAddressException::class, "CIDR", $createAPortForwardToANetwork];

$createAPortForwardFromPort0 = function () : void {
    new PortForward(0, "10.0.0.1", 80);
};

$cases[] = ["a port forward from port 0", BadArgumentException::class, "65535", $createAPortForwardFromPort0];

# Connection limits, element timeouts, dup, fwd, IPsec, ct expectations and accepting port forwards

$createAConnectionLimitOf0 = function () : void {
    new ConnectionLimitStatement(0, LimitMatch::OVER_LIMIT);
};

$cases[] = ["a connection limit of 0", BadArgumentException::class, "at least 1", $createAConnectionLimitOf0];

$createAConnectionLimitInASetWithATimeout = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withTimeout(60)->withSize(10);
    $limit = new ConnectionLimitStatement(5, LimitMatch::OVER_LIMIT);
    new SetUpdateStatement(SetUpdateOperation::ADD, $set, $saddr, $limit);
};

$cases[] = [
    "a connection limit in a set with a timeout",
    BadArgumentException::class,
    "can't have a timeout",
    $createAConnectionLimitInASetWithATimeout,
];

$createAConnectionLimitInASetWithNoSize = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR);
    $limit = new ConnectionLimitStatement(5, LimitMatch::OVER_LIMIT);
    new SetUpdateStatement(SetUpdateOperation::ADD, $set, $saddr, $limit);
};

$cases[] = [
    "a connection limit in a set with no size",
    BadArgumentException::class,
    "withSize",
    $createAConnectionLimitInASetWithNoSize,
];

$createAnElementTimeoutOf0 = function () : void {
    new TimedElement("10.0.0.1", 0);
};

$cases[] = ["an element timeout of 0", BadArgumentException::class, "at least 1 second", $createAnElementTimeoutOf0];

$createATimedElementInASetWithNoTimeout = function () use ($ipTable) : void {
    NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withElements(new TimedElement("10.0.0.1", 60));
};

$cases[] = [
    "a timed element in a set with no timeout",
    BadArgumentException::class,
    "withTimeout()",
    $createATimedElementInASetWithNoTimeout,
];

$createDeletingATimedElement = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withTimeout(60);
    new SetUpdateStatement(SetUpdateOperation::DELETE, $set, new TimedElement($saddr, 10));
};

$cases[] = [
    "deleting a timed element",
    BadArgumentException::class,
    "can't apply statements or a timeout",
    $createDeletingATimedElement,
];

$createATimedElementInASetUpdateWithNoTimeout = function () use ($ipTable, $saddr) : void {
    $set = NamedSet::create($ipTable, "s", SetType::IPV4_ADDR)->withSize(10);
    $limit = new ConnectionLimitStatement(5, LimitMatch::OVER_LIMIT);
    new SetUpdateStatement(SetUpdateOperation::ADD, $set, new TimedElement($saddr, 10), $limit);
};

$cases[] = [
    "a timed element in a set update with no timeout",
    BadArgumentException::class,
    "in a set with a timeout",
    $createATimedElementInASetUpdateWithNoTimeout,
];

$createACopyToANetwork = function () : void {
    DupStatement::createToAddress("10.0.0.0/8");
};

$cases[] = ["a copy to a network", InvalidAddressException::class, "network CIDR", $createACopyToANetwork];

$createACopyInAnInetTable = function () : void {
    Rule::create(Fixtures::createInputChain(new Table("i", Family::INET)), DupStatement::createToAddress("10.0.0.9"));
};

$cases[] = [
    "a copy in an inet table",
    UnsuitableChainException::class,
    "the ip family, not inet",
    $createACopyInAnInetTable,
];

$createACopyToADeviceInAnIpTable = function () use ($input) : void {
    Rule::create($input, DupStatement::createToDevice("eth1"));
};

$cases[] = [
    "a copy to a device in an ip table",
    UnsuitableChainException::class,
    "the netdev family, not ip",
    $createACopyToADeviceInAnIpTable,
];

$createACopyToA16ByteDeviceName = function () : void {
    DupStatement::createToDevice("a-sixteen-bytes!");
};

$cases[] = [
    "a copy to a 16 byte device name",
    BadArgumentException::class,
    "15 bytes",
    $createACopyToA16ByteDeviceName,
];

$createForwardingToADeviceInAnIpTable = function () use ($input) : void {
    Rule::create($input, FwdStatement::createToDevice("eth1"));
};

$cases[] = [
    "forwarding to a device in an ip table",
    UnsuitableChainException::class,
    "netdev table",
    $createForwardingToADeviceInAnIpTable,
];

$createForwardingToANetwork = function () : void {
    FwdStatement::createToAddress("eth1", "10.0.0.0/8");
};

$cases[] = ["forwarding to a network", InvalidAddressException::class, "network CIDR", $createForwardingToANetwork];

$createAnIPsecAssociationNumberOf256 = function () : void {
    IpsecExpression::create(IpsecDirection::IN, IpsecKey::REQID, 256);
};

$cases[] = [
    "an IPsec association number of 256",
    BadArgumentException::class,
    "from 0 to 255",
    $createAnIPsecAssociationNumberOf256,
];

$createAnIPv6CtExpectationInAnIpTable = function () use ($ipTable) : void {
    new CtExpectation("e", $ipTable, IpVersion::IPV6, Protocol::TCP, 22, 60, 1);
};

$cases[] = [
    "an IPv6 ct expectation in an ip table",
    BadArgumentException::class,
    "can't be for IPV6",
    $createAnIPv6CtExpectationInAnIpTable,
];

$createACtExpectationForPort0 = function () use ($ipTable) : void {
    new CtExpectation("e", $ipTable, IpVersion::IPV4, Protocol::TCP, 0, 60, 1);
};

$cases[] = ["a ct expectation for port 0", BadArgumentException::class, "65535", $createACtExpectationForPort0];

$createACtExpectationFor256Connections = function () use ($ipTable) : void {
    new CtExpectation("e", $ipTable, IpVersion::IPV4, Protocol::TCP, 22, 60, 256);
};

$cases[] = [
    "a ct expectation for 256 connections",
    BadArgumentException::class,
    "from 1 to 255",
    $createACtExpectationFor256Connections,
];

$createACtExpectationWithNoTimeout = function () use ($ipTable) : void {
    new CtExpectation("e", $ipTable, IpVersion::IPV4, Protocol::TCP, 22, 0, 1);
};

$cases[] = [
    "a ct expectation with no timeout",
    BadArgumentException::class,
    "at least 1 second",
    $createACtExpectationWithNoTimeout,
];

$createABridgeCtExpectation = function () : void {
    new CtExpectation("e", new Table("b", Family::BRIDGE), IpVersion::IPV4, Protocol::TCP, 22, 60, 1);
};

$cases[] = ["a bridge ct expectation", BadArgumentException::class, "ip, ip6 or inet", $createABridgeCtExpectation];

$createAcceptingPortForwardsInAnInputChain = function () use ($input) : void {
    RuleFactory::createAcceptPortForwards($input);
};

$cases[] = [
    "accepting port forwards in an input chain",
    UnsuitableChainException::class,
    "forward hook",
    $createAcceptingPortForwardsInAnInputChain,
];

foreach ($cases as [$description, $exceptionClass, $messageContains, $code])
{
    $test = function () use ($exceptionClass, $code, $messageContains) : void {
        SmokeTestRunner::expectException($exceptionClass, $code, $messageContains);
    };

    $smoke->run("Validation: {$description} is rejected", $test);
}

# Bugs fixed in 1.0.0

$testForwardDestination = function () use ($ipTable) : void {
    // It used to match the source address against the destination, or throw if only the destination was given.
    $forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
    $addresses = ["sourceAddress" => "10.0.0.9", "destinationAddress" => "10.0.0.5"];
    $rule = RuleFactory::createForward($forward, "eth0", "eth1", ...$addresses);
    $matches = Fixtures::getRuleExpressions($rule);
    SmokeTestRunner::assertSame("saddr", $matches[2]["match"]["left"]["payload"]["field"], "the 3rd match's field");
    SmokeTestRunner::assertSame("10.0.0.9", $matches[2]["match"]["right"], "the source address");
    SmokeTestRunner::assertSame("daddr", $matches[3]["match"]["left"]["payload"]["field"], "the 4th match's field");
    SmokeTestRunner::assertSame("10.0.0.5", $matches[3]["match"]["right"], "the destination address");
};

$smoke->run("Bugs: createForward() matches the destination address, not the source", $testForwardDestination);

$testForwardVerdict = function () use ($ipTable) : void {
    // It used to have no verdict, so the rule matched packets but did nothing with them.
    $forward = Fixtures::createBaseChain($ipTable, ChainType::FILTER, ChainHook::FORWARD);
    $expressions = Fixtures::getRuleExpressions(RuleFactory::createForward($forward, "eth0", "eth1"));
    SmokeTestRunner::assertSame(["accept" => null], end($expressions), "the last statement");
};

$smoke->run("Bugs: createForward() ends with an accept verdict", $testForwardVerdict);

$testDuplicatesGiveLists = function () : void {
    // array_unique() used to leave gaps in the keys, which json_encode() turned into an object.
    $ports = MatchFactory::createDestinationPorts(Protocol::TCP, new PortSet(22, 22, 80))->toArray();
    $states = new ConnectionStateSet(ConnectionState::NEW, ConnectionState::NEW, ConnectionState::ESTABLISHED);
    SmokeTestRunner::assertSame('{"set":[22,80]}', json_encode($ports["match"]["right"]), "the ports' JSON");
    SmokeTestRunner::assertSame('["new","established"]', json_encode($states->toJsonValue()), "the states' JSON");
};

$smoke->run("Bugs: duplicate ports and states give JSON lists, not objects", $testDuplicatesGiveLists);

$testIpv6Matches = function () : void {
    // Address matches used to always use the ip (IPv4) header, which nft rejects in an ip6 table.
    $match = MatchFactory::createSourceAddress("2001:db8::1")->toArray();
    SmokeTestRunner::assertSame("ip6", $match["match"]["left"]["payload"]["protocol"], "the header");
    SmokeTestRunner::assertSame(IpVersion::IPV6, NetworkLib::getIpVersion("fd00::/8"), "the version of fd00::/8");
    SmokeTestRunner::assertSame(IpVersion::IPV4, NetworkLib::getIpVersion("10.0.0.0/8"), "the version of 10.0.0.0/8");
};

$smoke->run("Bugs: address matches use the ip6 header for IPv6 addresses", $testIpv6Matches);

$testNetworkCidrs = function () : void {
    SmokeTestRunner::assertTrue(NetworkLib::isValidNetworkCidr("10.0.0.0/8"), "10.0.0.0/8 is a network");
    SmokeTestRunner::assertTrue(!NetworkLib::isValidNetworkCidr("10.0.0.1/8"), "10.0.0.1/8 isn't a network");
    SmokeTestRunner::assertTrue(NetworkLib::isValidCidr("10.0.0.1/8"), "10.0.0.1/8 is a CIDR");
    SmokeTestRunner::assertTrue(!NetworkLib::isValidCidr("10.0.0.1"), "an address isn't a CIDR");
    SmokeTestRunner::assertTrue(NetworkLib::isValidNetworkCidr("fd00::/8"), "fd00::/8 is a network");
};

$smoke->run("Bugs: network CIDRs are told apart from host CIDRs", $testNetworkCidrs);

$testPriorityIsAnInteger = function () use ($ipTable) : void {
    // nft silently ignores a priority given as a name, and creates a chain with no hook that sees no packets.
    $chain = new BaseChain("c", $ipTable, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
    SmokeTestRunner::assertSame(-100, $chain->toArray()["chain"]["prio"], "the dstnat priority");
    $bridgeChain = Fixtures::createChain("c", new Table("b", Family::BRIDGE), Policy::ACCEPT);
    SmokeTestRunner::assertSame(-200, $bridgeChain->toArray()["chain"]["prio"], "the bridge filter priority");
};

$smoke->run("Bugs: named priorities are sent to nft as integers", $testPriorityIsAnInteger);
