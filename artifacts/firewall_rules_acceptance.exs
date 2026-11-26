#!/usr/bin/env elixir
# Standalone parity acceptance for the Elixir control-plane rule engine.
#
# Run with a plain Elixir install, no Mix/project dependencies required:
#   elixir artifacts/firewall_rules_acceptance.exs
#
# It loads the real `elixir/lib/portal/firewall_rules.ex` and verifies the
# same three group configurations plus conflict-dispatch rejection as the
# Rust/gateway acceptance.

root = Path.expand("..", __DIR__)
Code.require_file(Path.join(root, "elixir/lib/portal/firewall_rules.ex"))

alias Portal.FirewallRules
alias Portal.FirewallRules.{DeviceGroup, Flow, Matcher, Rule}

failures = Agent.start_link(fn -> [] end) |> elem(1)

check = fn condition, label ->
  if condition do
    IO.puts("  PASS  #{label}")
  else
    IO.puts("  FAIL  #{label}")
    Agent.update(failures, fn list -> [label | list] end)
  end
end

check_eq = fn actual, expected, label ->
  if actual == expected do
    IO.puts("  PASS  #{label}")
  else
    IO.puts(
      "  FAIL  #{label}\n        expected: #{inspect(expected)}\n        actual:   #{inspect(actual)}"
    )

    Agent.update(failures, fn list -> ["#{label} mismatch" | list] end)
  end
end

ids = fn resolution -> Enum.map(resolution.effective, & &1.rule_id) end

tcp = fn cidr, ports -> Matcher.new(protocol: :tcp, cidr: cidr, ports: ports) end

# Configuration 1 ---------------------------------------------------------
IO.puts("\n[config] single_group_specificity")

groups1 = [DeviceGroup.new("office", 10)]

rules1 = [
  Rule.new("allow-bastion-ssh", "office", :allow, tcp.("10.0.0.5/32", 22)),
  Rule.new("allow-internal-all-tcp", "office", :allow, tcp.("10.0.0.0/8", 0..65_535//1)),
  Rule.new("allow-web-https", "office", :allow, tcp.(nil, 443))
]

{:ok, one} = FirewallRules.resolve(groups1, rules1, ["office"])

check_eq.(
  ids.(one),
  [
    "allow-bastion-ssh",
    "allow-internal-all-tcp",
    "allow-web-https"
  ],
  "config 1 effective order"
)

check_eq.(FirewallRules.Resolution.verdict(one, Flow.tcp("10.0.0.5", 22)), :allow, "bastion ssh")

check_eq.(
  FirewallRules.Resolution.verdict(one, Flow.tcp("10.1.2.3", 8080)),
  :allow,
  "internal tcp"
)

check_eq.(FirewallRules.Resolution.verdict(one, Flow.tcp("8.8.8.8", 443)), :allow, "https")

check_eq.(
  FirewallRules.Resolution.verdict(one, Flow.tcp("8.8.8.8", 22)),
  :deny,
  "public ssh denied"
)

check_eq.(
  FirewallRules.Resolution.verdict(one, Flow.udp("8.8.8.8", 53)),
  :deny,
  "udp not granted"
)

# Configuration 2 ---------------------------------------------------------
IO.puts("\n[config] tiered_priority_override")

groups2 = [DeviceGroup.new("standard", 10), DeviceGroup.new("hardened", 100)]

rules2 = [
  Rule.new("std-allow-web", "standard", :allow, tcp.(nil, 443)),
  Rule.new("std-deny-ssh", "standard", :deny, tcp.(nil, 22)),
  Rule.new("hard-deny-web", "hardened", :deny, tcp.(nil, 443)),
  Rule.new("hard-allow-bastion", "hardened", :allow, tcp.("10.0.0.5/32", 22))
]

{:ok, two} = FirewallRules.resolve(groups2, rules2, ["standard", "hardened"])

check_eq.(
  ids.(two),
  [
    "hard-allow-bastion",
    "hard-deny-web",
    "std-allow-web",
    "std-deny-ssh"
  ],
  "config 2 effective order"
)

check_eq.(
  FirewallRules.Resolution.verdict(two, Flow.tcp("1.1.1.1", 443)),
  :deny,
  "high deny wins"
)

check_eq.(
  FirewallRules.Resolution.verdict(two, Flow.tcp("10.0.0.5", 22)),
  :allow,
  "high allow wins"
)

check_eq.(FirewallRules.Resolution.verdict(two, Flow.tcp("10.0.0.6", 22)), :deny, "bastion scope")

check_eq.(
  FirewallRules.Resolution.gateway_filters_json(two, "10.0.0.5"),
  ~s([{"protocol":"tcp","port_range_start":22,"port_range_end":22}]),
  "gateway wire filter"
)

check_eq.(
  FirewallRules.Resolution.gateway_filters(two, "10.0.0.6"),
  [],
  "fully denied scope has no allow filters"
)

# Configuration 3 ---------------------------------------------------------
IO.puts("\n[config] three_group_merge")

groups3 = [
  DeviceGroup.new("baseline", 0),
  DeviceGroup.new("engineering", 50),
  DeviceGroup.new("sre", 80)
]

rules3 = [
  Rule.new("base-dns", "baseline", :allow, Matcher.new(protocol: :udp, ports: 53)),
  Rule.new("base-ntp", "baseline", :allow, Matcher.new(protocol: :udp, ports: 123)),
  Rule.new("eng-registry", "engineering", :allow, tcp.("10.20.0.0/16", 5000)),
  Rule.disabled(Rule.new("eng-disabled", "engineering", :allow, tcp.(nil, 9999))),
  Rule.new("sre-deny-registry-prod", "sre", :deny, tcp.("10.20.1.0/24", 5000)),
  Rule.new("sre-allow-ssh", "sre", :allow, tcp.("10.0.0.0/8", 22))
]

{:ok, three} = FirewallRules.resolve(groups3, rules3, ["baseline", "engineering", "sre"])

check_eq.(
  ids.(three),
  [
    "sre-deny-registry-prod",
    "sre-allow-ssh",
    "eng-registry",
    "base-dns",
    "base-ntp"
  ],
  "config 3 effective order"
)

check_eq.(
  FirewallRules.Resolution.verdict(three, Flow.tcp("10.20.1.10", 5000)),
  :deny,
  "prod carved out"
)

check_eq.(
  FirewallRules.Resolution.verdict(three, Flow.tcp("10.20.2.10", 5000)),
  :allow,
  "non-prod allowed"
)

check_eq.(FirewallRules.Resolution.verdict(three, Flow.tcp("10.0.0.9", 22)), :allow, "sre ssh")

check_eq.(
  FirewallRules.Resolution.verdict(three, Flow.udp("8.8.8.8", 53)),
  :allow,
  "baseline dns"
)

check_eq.(
  FirewallRules.Resolution.verdict(three, Flow.tcp("8.8.8.8", 9999)),
  :deny,
  "disabled absent"
)

# Conflicts ---------------------------------------------------------------
IO.puts("\n[conflict] dispatch rejection")

conflict_request = %{
  gateway_id: "gw",
  client_id: "dev",
  resource_id: "res-db",
  groups: [DeviceGroup.new("a", 50), DeviceGroup.new("b", 50)],
  rules: [
    Rule.new("allow-db", "a", :allow, tcp.("10.1.2.0/24", 5432)),
    Rule.new("deny-db", "b", :deny, tcp.("10.1.2.3/32", 5432))
  ],
  member_group_ids: ["a", "b"],
  default_action: :deny,
  destinations: ["10.1.2.3"]
}

check.(
  match?(
    {:error, %{__struct__: Portal.FirewallRules.DispatchRejection}},
    FirewallRules.dispatch(conflict_request)
  ),
  "cross-group equal-priority conflict rejects dispatch"
)

same_group = [
  Rule.new("allow-ssh", "net", :allow, tcp.(nil, 22)),
  Rule.new("deny-ssh", "net", :deny, tcp.(nil, 22))
]

check.(
  match?(
    {:error, %{__struct__: Portal.FirewallRules.ConflictError, conflicts: [_]}},
    FirewallRules.resolve([DeviceGroup.new("net", 10)], same_group, ["net"])
  ),
  "same-group exact opposites are a conflict"
)

overlap = [
  Rule.new("allow-low", "x", :allow, tcp.(nil, 1..1024//1)),
  Rule.new("deny-ssh", "y", :deny, tcp.(nil, 22))
]

check.(
  match?(
    {:error, _},
    FirewallRules.resolve([DeviceGroup.new("x", 20), DeviceGroup.new("y", 20)], overlap, [
      "x",
      "y"
    ])
  ),
  "overlapping port ranges conflict"
)

disjoint = [
  Rule.new("allow-https", "ops", :allow, tcp.(nil, 443)),
  Rule.new("deny-ssh", "ops", :deny, tcp.(nil, 22))
]

check.(
  match?(
    {:ok, _},
    FirewallRules.resolve([DeviceGroup.new("ops", 30)], disjoint, ["ops"])
  ),
  "disjoint same-tier rules are not a false conflict"
)

failures = Agent.get(failures, & &1)

if failures == [] do
  IO.puts("\nELIXIR ACCEPTANCE PASSED")
else
  IO.puts("\nELIXIR ACCEPTANCE FAILED (#{length(failures)})")
  System.halt(1)
end
