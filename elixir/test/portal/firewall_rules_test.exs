defmodule Portal.FirewallRulesTest do
  use ExUnit.Case, async: true

  alias Portal.FirewallRules

  alias Portal.FirewallRules.{
    DeviceGroup,
    DispatchRequest,
    Flow,
    Matcher,
    Rule
  }

  defp group(id, priority, name \\ "") do
    DeviceGroup.new(id, priority, name)
  end

  defp rule(id, group_id, action, matcher) do
    Rule.new(id, group_id, action, matcher)
  end

  defp tcp_matcher(cidr, ports) do
    Matcher.new(protocol: :tcp, cidr: cidr, ports: ports)
  end

  defp effective_ids(resolution) do
    Enum.map(resolution.effective, & &1.rule_id)
  end

  describe "three group configurations" do
    test "configuration 1: single group, specificity order and default deny" do
      groups = [group("office", 10)]

      rules = [
        rule("allow-bastion-ssh", "office", :allow, tcp_matcher("10.0.0.5/32", 22)),
        rule("allow-internal-all-tcp", "office", :allow, tcp_matcher("10.0.0.0/8", 0..65_535//1)),
        rule("allow-web-https", "office", :allow, tcp_matcher(nil, 443))
      ]

      assert {:ok, resolution} =
               FirewallRules.resolve(groups, rules, ["office"], default_action: :deny)

      assert effective_ids(resolution) == [
               "allow-bastion-ssh",
               "allow-internal-all-tcp",
               "allow-web-https"
             ]

      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.0.0.5", 22)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.1.2.3", 8080)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("8.8.8.8", 443)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("8.8.8.8", 22)) == :deny
      assert FirewallRules.Resolution.verdict(resolution, Flow.udp("8.8.8.8", 53)) == :deny
    end

    test "configuration 2: distinct priorities override in both directions" do
      groups = [group("standard", 10), group("hardened", 100)]

      rules = [
        rule("std-allow-web", "standard", :allow, tcp_matcher(nil, 443)),
        rule("std-deny-ssh", "standard", :deny, tcp_matcher(nil, 22)),
        rule("hard-deny-web", "hardened", :deny, tcp_matcher(nil, 443)),
        rule("hard-allow-bastion", "hardened", :allow, tcp_matcher("10.0.0.5/32", 22))
      ]

      assert {:ok, resolution} =
               FirewallRules.resolve(groups, rules, ["standard", "hardened"],
                 default_action: :deny
               )

      assert effective_ids(resolution) == [
               "hard-allow-bastion",
               "hard-deny-web",
               "std-allow-web",
               "std-deny-ssh"
             ]

      assert hd(resolution.effective).rule_id == "hard-allow-bastion"

      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("1.1.1.1", 443)) == :deny
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.0.0.5", 22)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.0.0.6", 22)) == :deny
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("1.1.1.1", 80)) == :deny

      bastion_filters =
        FirewallRules.Resolution.gateway_filters_json(resolution, "10.0.0.5")

      assert bastion_filters ==
               ~s([{"protocol":"tcp","port_range_start":22,"port_range_end":22}])

      assert FirewallRules.Resolution.gateway_filters(resolution, "10.0.0.6") == []
    end

    test "configuration 3: three groups merge with a cross-tier carve-out" do
      groups = [group("baseline", 0), group("engineering", 50), group("sre", 80)]

      rules = [
        rule("base-dns", "baseline", :allow, Matcher.new(protocol: :udp, ports: 53)),
        rule("base-ntp", "baseline", :allow, Matcher.new(protocol: :udp, ports: 123)),
        rule("eng-registry", "engineering", :allow, tcp_matcher("10.20.0.0/16", 5000)),
        Rule.disabled(
          rule("eng-disabled-tailnet", "engineering", :allow, tcp_matcher(nil, 9999))
        ),
        rule("sre-deny-registry-prod", "sre", :deny, tcp_matcher("10.20.1.0/24", 5000)),
        rule("sre-allow-ssh", "sre", :allow, tcp_matcher("10.0.0.0/8", 22))
      ]

      assert {:ok, resolution} =
               FirewallRules.resolve(groups, rules, ["baseline", "engineering", "sre"],
                 default_action: :deny
               )

      assert effective_ids(resolution) == [
               "sre-deny-registry-prod",
               "sre-allow-ssh",
               "eng-registry",
               "base-dns",
               "base-ntp"
             ]

      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.20.1.10", 5000)) == :deny
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.20.2.10", 5000)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("10.0.0.9", 22)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("11.0.0.9", 22)) == :deny
      assert FirewallRules.Resolution.verdict(resolution, Flow.udp("8.8.8.8", 53)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("8.8.8.8", 9999)) == :deny
    end
  end

  describe "conflict configurations are rejected" do
    test "same priority cross-group opposing overlap returns all conflicts" do
      groups = [group("a", 50), group("b", 50)]

      rules = [
        rule("allow-db", "a", :allow, tcp_matcher("10.1.2.0/24", 5432)),
        rule("deny-db", "b", :deny, tcp_matcher("10.1.2.3/32", 5432))
      ]

      assert {:error, error} = FirewallRules.resolve(groups, rules, ["a", "b"])
      assert length(error.conflicts) == 1
      assert hd(error.conflicts).rule_a == "allow-db"
      assert hd(error.conflicts).rule_b == "deny-db"
      assert hd(error.conflicts).priority == 50

      assert_raise Portal.FirewallRules.ConflictError, ~r/firewall rule conflict/, fn ->
        FirewallRules.resolve!(groups, rules, ["a", "b"])
      end
    end

    test "dispatch refuses conflicting rules and emits no gateway payload" do
      request = %DispatchRequest{
        gateway_id: "gw-1",
        client_id: "dev-1",
        resource_id: "res-ssh",
        groups: [group("a", 50), group("b", 50)],
        rules: [
          rule("allow-ssh", "a", :allow, tcp_matcher(nil, 22)),
          rule("deny-ssh", "b", :deny, tcp_matcher(nil, 22))
        ],
        member_group_ids: ["a", "b"],
        destinations: ["10.0.0.1"]
      }

      assert {:error, rejection} = FirewallRules.dispatch(request)
      assert rejection.message =~ "dispatch rejected"
      assert length(rejection.conflicts) == 1
    end

    test "identical allow/deny in the same group is a conflict (last write must not win)" do
      groups = [group("net", 10)]

      rules = [
        rule("allow-ssh", "net", :allow, tcp_matcher(nil, 22)),
        rule("deny-ssh", "net", :deny, tcp_matcher(nil, 22))
      ]

      assert {:error, error} = FirewallRules.resolve(groups, rules, ["net"])
      assert [%{rule_a: "allow-ssh", rule_b: "deny-ssh"}] = error.conflicts
    end

    test "overlapping port ranges at equal priority conflict" do
      groups = [group("x", 20), group("y", 20)]

      rules = [
        rule("allow-low-ports", "x", :allow, tcp_matcher(nil, 1..1024//1)),
        rule("deny-ssh", "y", :deny, tcp_matcher(nil, 22))
      ]

      assert {:error, error} = FirewallRules.resolve(groups, rules, ["x", "y"])
      assert length(error.conflicts) == 1
    end

    test "disjoint same-priority allow and deny are not flagged" do
      groups = [group("ops", 30)]

      rules = [
        rule("allow-https", "ops", :allow, tcp_matcher(nil, 443)),
        rule("deny-ssh", "ops", :deny, tcp_matcher(nil, 22))
      ]

      assert {:ok, resolution} = FirewallRules.resolve(groups, rules, ["ops"])
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("1.1.1.1", 443)) == :allow
      assert FirewallRules.Resolution.verdict(resolution, Flow.tcp("1.1.1.1", 22)) == :deny
    end
  end

  describe "gateway compatibility" do
    test "dispatch emits allow_access filters and reject_access for fully denied scopes" do
      request = %DispatchRequest{
        groups: [group("standard", 10), group("hardened", 100)],
        rules: [
          rule("std-allow-web", "standard", :allow, tcp_matcher(nil, 443)),
          rule("std-deny-ssh", "standard", :deny, tcp_matcher(nil, 22)),
          rule("hard-deny-web", "hardened", :deny, tcp_matcher(nil, 443)),
          rule("hard-allow-bastion", "hardened", :allow, tcp_matcher("10.0.0.5/32", 22))
        ],
        member_group_ids: ["standard", "hardened"],
        destinations: ["10.0.0.5", "10.0.0.6"],
        client_id: "device-42",
        resource_id: "res-1"
      }

      assert {:ok, receipt} = FirewallRules.dispatch(request)
      assert ["allow_access", "reject_access"] = Enum.map(receipt.destinations, & &1.event)

      message = hd(receipt.destinations).message
      assert message =~ ~s("event":"allow_access")
      assert message =~ ~s("port_range_start":22)
      assert message =~ ~s("client_id":"device-42")
    end
  end
end
