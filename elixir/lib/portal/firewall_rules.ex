defmodule Portal.FirewallRules.Cidr do
  @moduledoc """
  Parsed CIDR selector with bitwise containment/overlap checks.

  This is intentionally dependency-free so the rule engine can be validated
  without a database or the rest of the portal application.
  """

  import Bitwise

  @enforce_keys [:network_int, :prefix, :bits]
  defstruct network_int: 0, prefix: 0, bits: 32

  def parse(input) when is_binary(input) do
    with [address_binary, prefix_binary] <- String.split(input, "/", parts: 2),
         {:ok, address_tuple} <- :inet.parse_address(String.to_charlist(address_binary)),
         {prefix, ""} <- Integer.parse(prefix_binary) do
      bits = if tuple_size(address_tuple) == 4, do: 32, else: 128

      if prefix < 0 or prefix > bits do
        {:error, "prefix /#{prefix} exceeds /#{bits} in #{input}"}
      else
        address_int = tuple_to_int(address_tuple, bits)

        {:ok,
         %__MODULE__{
           network_int: network_int(address_int, bits, prefix),
           prefix: prefix,
           bits: bits
         }}
      end
    else
      _ -> {:error, "invalid CIDR: #{input}"}
    end
  end

  def parse!(input) do
    case parse(input) do
      {:ok, cidr} -> cidr
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  def contains?(%__MODULE__{bits: bits, prefix: prefix, network_int: network}, ip_tuple)
      when is_tuple(ip_tuple) do
    ip_bits = if tuple_size(ip_tuple) == 4, do: 32, else: 128

    if ip_bits != bits do
      false
    else
      host_bits = bits - prefix
      ip_int = tuple_to_int(ip_tuple, bits)
      ip_int >>> host_bits == network >>> host_bits
    end
  end

  def contains?(cidr, ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} -> contains?(cidr, tuple)
      {:error, _} -> false
    end
  end

  def overlaps?(%__MODULE__{bits: same_bits} = a, %__MODULE__{bits: same_bits} = b) do
    contains_network?(a, b.network_int) or contains_network?(b, a.network_int)
  end

  def overlaps?(_a, _b), do: false

  defp contains_network?(%__MODULE__{prefix: prefix, bits: bits, network_int: network}, int) do
    host_bits = bits - prefix
    int >>> host_bits == network >>> host_bits
  end

  defp network_int(int, bits, prefix) do
    host_bits = bits - prefix
    (int >>> host_bits) <<< host_bits
  end

  defp tuple_to_int(tuple, bits) do
    unit = div(bits, tuple_size(tuple))

    tuple
    |> Tuple.to_list()
    |> Enum.reduce(0, fn part, acc -> (acc <<< unit) + part end)
  end
end

defmodule Portal.FirewallRules.Matcher do
  @moduledoc "Traffic matcher: protocol + optional destination CIDR + optional port range."

  alias Portal.FirewallRules.Cidr

  @type protocol :: :tcp | :udp | :icmp | :any

  defstruct protocol: :any, cidr: nil, ports: nil

  def new(attrs \\ []) do
    attrs =
      attrs
      |> Keyword.update(:protocol, :any, &parse_protocol!/1)
      |> Keyword.update(:cidr, nil, &maybe_parse_cidr/1)
      |> Keyword.update(:ports, nil, &normalize_ports/1)

    struct!(__MODULE__, attrs)
  end

  def parse_protocol!(value) when value in [:tcp, :udp, :icmp, :any], do: value

  def parse_protocol!(value) when is_binary(value) do
    case String.downcase(value) do
      "tcp" -> :tcp
      "udp" -> :udp
      "icmp" -> :icmp
      "any" -> :any
      "*" -> :any
      "all" -> :any
      other -> raise ArgumentError, "unknown protocol #{inspect(other)}"
    end
  end

  def overlaps?(%__MODULE__{} = a, %__MODULE__{} = b) do
    protocol_intersect?(a.protocol, b.protocol) and
      cidr_overlap?(a.cidr, b.cidr) and
      port_overlap?(a.ports, b.ports)
  end

  def matches_flow?(%__MODULE__{} = matcher, flow) do
    protocol_intersect?(matcher.protocol, flow.protocol) and
      cidr_match?(matcher.cidr, flow.destination) and
      port_match?(matcher.ports, flow.port)
  end

  def prefix_len(%__MODULE__{cidr: nil}), do: 0
  def prefix_len(%__MODULE__{cidr: %Cidr{prefix: prefix}}), do: prefix

  def port_width(%__MODULE__{ports: nil}), do: 65_536
  def port_width(%__MODULE__{ports: %Range{first: first, last: last}}), do: last - first + 1

  defp protocol_intersect?(:any, _other), do: true
  defp protocol_intersect?(_one, :any), do: true
  defp protocol_intersect?(same, same), do: true
  defp protocol_intersect?(_a, _b), do: false

  defp cidr_overlap?(nil, _), do: true
  defp cidr_overlap?(_, nil), do: true
  defp cidr_overlap?(%Cidr{} = a, %Cidr{} = b), do: Cidr.overlaps?(a, b)

  defp port_overlap?(nil, _), do: true
  defp port_overlap?(_, nil), do: true

  defp port_overlap?(%Range{first: a_first, last: a_last}, %Range{
         first: b_first,
         last: b_last
       }) do
    a_first <= b_last and b_first <= a_last
  end

  defp cidr_match?(nil, _ip), do: true
  defp cidr_match?(%Cidr{} = cidr, ip), do: Cidr.contains?(cidr, ip)

  defp port_match?(nil, _port), do: true
  defp port_match?(%Range{} = range, port) when is_integer(port), do: port in range
  defp port_match?(_range, _port), do: false

  defp maybe_parse_cidr(nil), do: nil
  defp maybe_parse_cidr(%Cidr{} = cidr), do: cidr
  defp maybe_parse_cidr(value) when is_binary(value), do: Cidr.parse!(value)

  defp normalize_ports(nil), do: nil
  defp normalize_ports(%Range{} = range), do: range
  defp normalize_ports(port) when is_integer(port), do: port..port//1
  defp normalize_ports({first, last}), do: first..last//1
end

defmodule Portal.FirewallRules.DeviceGroup do
  @moduledoc "A device group with an explicit precedence; higher priority wins."
  @enforce_keys [:id, :priority]
  defstruct [:id, :priority, name: ""]

  def new(id, priority, name \\ "") do
    %__MODULE__{id: id, priority: priority, name: name}
  end
end

defmodule Portal.FirewallRules.Rule do
  @moduledoc "A firewall rule (allow/deny) attached to one device group."
  alias Portal.FirewallRules.Matcher

  @enforce_keys [:id, :group_id, :action]
  defstruct [:id, :group_id, :action, matcher: %Matcher{}, enabled: true]

  def new(id, group_id, action, matcher \\ %Matcher{}) do
    %__MODULE__{id: id, group_id: group_id, action: normalize_action(action), matcher: matcher}
  end

  def disabled(%__MODULE__{} = rule), do: %{rule | enabled: false}

  def normalize_action(:allow), do: :allow
  def normalize_action(:deny), do: :deny

  def normalize_action(value) when is_binary(value) do
    case String.downcase(value) do
      v when v in ["allow", "accept", "permit"] -> :allow
      v when v in ["deny", "drop", "reject"] -> :deny
      other -> raise ArgumentError, "unknown action #{inspect(other)}"
    end
  end
end

defmodule Portal.FirewallRules.Flow do
  @moduledoc "A concrete flow used for verdict assertions."
  @enforce_keys [:protocol, :destination]
  defstruct [:protocol, :destination, port: nil]

  def tcp(ip, port), do: %__MODULE__{protocol: :tcp, destination: ip, port: port}
  def udp(ip, port), do: %__MODULE__{protocol: :udp, destination: ip, port: port}
  def icmp(ip), do: %__MODULE__{protocol: :icmp, destination: ip}
end

defmodule Portal.FirewallRules.Conflict do
  @moduledoc "Describes one unresolved same-precedence opposing overlap."
  @enforce_keys [:rule_a, :rule_b, :group_a, :group_b, :priority, :reason]
  defstruct [:rule_a, :rule_b, :group_a, :group_b, :priority, :reason]

  def describe(%__MODULE__{} = c) do
    "conflicting rules `#{c.rule_a}` (#{c.group_a}, priority #{c.priority}) and " <>
      "`#{c.rule_b}` (#{c.group_b}, priority #{c.priority}): #{c.reason}"
  end
end

defmodule Portal.FirewallRules.ConflictError do
  @moduledoc "Raised / returned when a dispatch contains hard rule conflicts."
  defexception message: "firewall rule conflict", conflicts: []

  @impl true
  def message(%__MODULE__{message: message, conflicts: conflicts}) do
    if conflicts == [] do
      message
    else
      details =
        Enum.map_join(conflicts, "\n", fn c ->
          "  - " <> Portal.FirewallRules.Conflict.describe(c)
        end)

      "#{length(conflicts)} firewall rule conflict(s):\n#{details}"
    end
  end
end

defmodule Portal.FirewallRules.GatewayFilter do
  @moduledoc "Mirrors connlib `messages::Filter` JSON tags."
  @enforce_keys [:protocol]
  defstruct [:protocol, start: nil, end: nil]

  def to_json(%__MODULE__{protocol: :icmp}) do
    ~s({"protocol":"icmp"})
  end

  def to_json(%__MODULE__{protocol: protocol, start: start, end: finish}) do
    ~s({"protocol":"#{protocol}","port_range_start":#{start},"port_range_end":#{finish}})
  end

  def to_json_array(filters) do
    body = filters |> Enum.map(&to_json/1) |> Enum.join(",")
    "[#{body}]"
  end
end

defmodule Portal.FirewallRules.Resolution do
  @moduledoc "A conflict-free, precedence-ordered policy."
  defstruct default_action: :deny, ordered: [], effective: []

  alias Portal.FirewallRules.Matcher

  def verdict(%__MODULE__{ordered: ordered, default_action: default_action}, flow) do
    case Enum.find(ordered, fn entry -> Matcher.matches_flow?(entry.rule.matcher, flow) end) do
      nil -> default_action
      entry -> entry.rule.action
    end
  end

  @doc """
  Project the policy for one destination onto the existing gateway `Filter`
  wire shape (`protocol` + `port_range_start`/`port_range_end`).
  """
  def gateway_filters(%__MODULE__{} = policy, destination) do
    tcp = port_filters(policy, destination, :tcp)
    udp = port_filters(policy, destination, :udp)

    icmp =
      case icmp_decision(policy, destination) do
        :allow -> [%Portal.FirewallRules.GatewayFilter{protocol: :icmp}]
        _ -> []
      end

    tcp ++ udp ++ icmp
  end

  def gateway_filters_json(policy, destination) do
    Portal.FirewallRules.GatewayFilter.to_json_array(gateway_filters(policy, destination))
  end

  defp port_filters(policy, destination, protocol) do
    decided = decide_ports(policy, destination, protocol)
    default_code = if policy.default_action == :allow, do: 1, else: 2

    0..65_535
    |> Enum.map(fn port -> {port, Map.get(decided, port, default_code)} end)
    |> allow_runs(protocol)
  end

  defp decide_ports(policy, destination, protocol) do
    Enum.reduce(policy.ordered, %{}, fn entry, decided ->
      rule = entry.rule
      matcher = rule.matcher

      if protocol_intersect?(matcher.protocol, protocol) and
           cidr_allows?(matcher.cidr, destination) do
        range = matcher.ports || 0..65_535//1
        code = if rule.action == :allow, do: 1, else: 2

        Enum.reduce(range, decided, fn port, acc ->
          Map.put_new(acc, port, code)
        end)
      else
        decided
      end
    end)
  end

  defp allow_runs(port_codes, protocol) do
    port_codes
    |> Enum.chunk_by(fn {_port, code} -> code end)
    |> Enum.filter(fn [{_port, code} | _] -> code == 1 end)
    |> Enum.map(fn chunk ->
      start = chunk |> List.first() |> elem(0)
      finish = chunk |> List.last() |> elem(0)

      %Portal.FirewallRules.GatewayFilter{
        protocol: protocol,
        start: start,
        end: finish
      }
    end)
  end

  defp icmp_decision(policy, destination) do
    decision =
      Enum.reduce_while(policy.ordered, nil, fn entry, current ->
        matcher = entry.rule.matcher

        if protocol_intersect?(matcher.protocol, :icmp) and
             cidr_allows?(matcher.cidr, destination) do
          {:halt, entry.rule.action}
        else
          {:cont, current}
        end
      end)

    decision || policy.default_action
  end

  defp protocol_intersect?(:any, _), do: true
  defp protocol_intersect?(_, :any), do: true
  defp protocol_intersect?(same, same), do: true
  defp protocol_intersect?(_, _), do: false

  defp cidr_allows?(nil, _destination), do: true

  defp cidr_allows?(%Portal.FirewallRules.Cidr{} = cidr, ip),
    do: Portal.FirewallRules.Cidr.contains?(cidr, ip)
end

defmodule Portal.FirewallRules.DispatchRequest do
  @moduledoc "Inputs for the explicit dispatch entry point."
  defstruct gateway_id: "gateway",
            client_id: "client",
            resource_id: "resource",
            groups: [],
            rules: [],
            member_group_ids: [],
            default_action: :deny,
            destinations: []
end

defmodule Portal.FirewallRules.DispatchRejection do
  @moduledoc "Returned when a conflicting config must not be dispatched."
  defexception message: "refusing to dispatch firewall rules", conflicts: []

  @impl true
  def message(%__MODULE__{message: message}), do: message
end

defmodule Portal.FirewallRules do
  @moduledoc """
  Device-group aware firewall rule resolution with hard conflict detection.

  Operational reports described rules that "look present but do not take
  effect"; the root cause was conflicting rules being collapsed into a map
  where the last write silently won.

  Semantics:

    * `Portal.FirewallRules.DeviceGroup` carries an explicit `:priority`;
      higher values win.
    * Opposing allow/deny overlaps at the *same* priority are conflicts.
      `resolve/4` returns `{:error, conflicts}` and `dispatch/1` refuses to
      produce a gateway payload.
    * Opposing overlaps at *different* priorities resolve deterministically:
      the higher-priority rule wins and the lower one is reported as shadowed.
    * The resolved policy projects onto the existing gateway `Filter` wire
      format, so current gateways stay compatible.
  """

  alias Portal.FirewallRules.{
    Conflict,
    ConflictError,
    DispatchRejection,
    DispatchRequest,
    Matcher,
    Resolution
  }

  @doc "Resolve with default posture `:deny`."
  def resolve(groups, rules, member_group_ids) do
    resolve(groups, rules, member_group_ids, default_action: :deny)
  end

  @doc """
  Resolve rules for a device belonging to `member_group_ids`.

  The fourth argument is either `:allow`/`:deny` or a keyword list such as
  `[default_action: :deny]`.
  """
  def resolve(groups, rules, member_group_ids, default_action)
      when default_action in [:allow, :deny] do
    resolve(groups, rules, member_group_ids, default_action: default_action)
  end

  def resolve(groups, rules, member_group_ids, opts) when is_list(opts) do
    default_action = Keyword.get(opts, :default_action, :deny)
    member_set = MapSet.new(member_group_ids)

    with :ok <- validate(groups, rules, member_group_ids) do
      candidates =
        rules
        |> Enum.filter(& &1.enabled)
        |> Enum.filter(&MapSet.member?(member_set, &1.group_id))
        |> Enum.map(fn rule -> {rule, priority_of(groups, rule.group_id)} end)

      conflicts = detect_conflicts(candidates)

      if conflicts != [] do
        {:error,
         %ConflictError{
           conflicts: conflicts,
           message: ConflictError.message(%ConflictError{conflicts: conflicts})
         }}
      else
        ordered = order_candidates(candidates)

        effective =
          ordered
          |> Enum.with_index(1)
          |> Enum.map(fn {{rule, priority}, order} ->
            shadows = shadows_for(ordered, order - 1, rule)

            %{
              order: order,
              rule_id: rule.id,
              group_id: rule.group_id,
              priority: priority,
              action: rule.action,
              shadows: shadows
            }
          end)

        {:ok,
         %Resolution{
           default_action: default_action,
           ordered: ordered_entries(ordered),
           effective: effective
         }}
      end
    end
  end

  @doc "Raising variant of `resolve/4`."
  def resolve!(groups, rules, member_group_ids, opts \\ []) do
    case resolve(groups, rules, member_group_ids, opts) do
      {:ok, resolution} -> resolution
      {:error, error} -> raise error
    end
  end

  @doc "Return the list of conflicts (empty list means the config is safe)."
  def detect_conflicts(groups, rules, member_group_ids) do
    case resolve(groups, rules, member_group_ids) do
      {:ok, _} -> []
      {:error, %ConflictError{conflicts: conflicts}} -> conflicts
    end
  end

  @doc """
  Validate and resolve, then build gateway-compatible payloads.

  Returns `{:error, %DispatchRejection{}}` for conflicts; never returns an
  `allow_access` payload for a conflicting configuration.
  """
  def dispatch(%DispatchRequest{} = request) do
    result =
      resolve(
        request.groups,
        request.rules,
        request.member_group_ids,
        default_action: request.default_action
      )

    case result do
      {:error, %ConflictError{} = error} ->
        conflicts = error.conflicts

        reason =
          if conflicts == [] do
            Exception.message(error)
          else
            "#{length(conflicts)} firewall rule conflict(s); dispatch rejected"
          end

        rejection = %DispatchRejection{
          conflicts: conflicts,
          message: reason
        }

        {:error, rejection}

      {:ok, resolution} ->
        destinations =
          Enum.map(request.destinations, fn destination ->
            filters = Resolution.gateway_filters(resolution, destination)
            filters_json = Resolution.gateway_filters_json(resolution, destination)

            if filters == [] do
              %{
                destination: destination,
                event: "reject_access",
                filters_json: "[]",
                message:
                  ~s({"event":"reject_access","client_id":"#{request.client_id}","resource_id":"#{request.resource_id}"})
              }
            else
              %{
                destination: destination,
                event: "allow_access",
                filters_json: filters_json,
                message:
                  ~s({"event":"allow_access","client_id":"#{request.client_id}","resource_id":"#{request.resource_id}","filters":#{filters_json}})
              }
            end
          end)

        effective_rule_ids = Enum.map(resolution.effective, & &1.rule_id)

        {:ok,
         %{
           gateway_id: request.gateway_id,
           client_id: request.client_id,
           resource_id: request.resource_id,
           effective_rule_ids: effective_rule_ids,
           destinations: destinations
         }}
    end
  end

  def dispatch(attrs) when is_list(attrs) or is_map(attrs) do
    dispatch(struct!(DispatchRequest, attrs))
  end

  defp validate(groups, rules, member_group_ids) do
    group_ids = MapSet.new(groups, & &1.id)

    unknown_member =
      Enum.find(member_group_ids, fn id -> not MapSet.member?(group_ids, id) end)

    cond do
      unknown_member ->
        {:error,
         %Portal.FirewallRules.ConflictError{message: "unknown device group #{unknown_member}"}}

      duplicate_rule_id?(rules) ->
        id =
          rules
          |> Enum.map(& &1.id)
          |> Enum.frequencies()
          |> Enum.find(fn {_id, count} -> count > 1 end)
          |> elem(0)

        {:error,
         %Portal.FirewallRules.ConflictError{
           message: "duplicate rule id `#{id}`; refusing to overwrite"
         }}

      unknown_rule_group?(groups, rules) ->
        group_id =
          rules
          |> Enum.find(fn rule -> is_nil(priority_of(groups, rule.group_id)) end)
          |> Map.fetch!(:group_id)

        {:error,
         %Portal.FirewallRules.ConflictError{
           message: "rule references unknown device group `#{group_id}`"
         }}

      true ->
        :ok
    end
  end

  defp duplicate_rule_id?(rules) do
    rules
    |> Enum.map(& &1.id)
    |> Enum.frequencies()
    |> Enum.any?(fn {_id, count} -> count > 1 end)
  end

  defp unknown_rule_group?(groups, rules) do
    Enum.any?(rules, fn rule -> is_nil(priority_of(groups, rule.group_id)) end)
  end

  defp priority_of(groups, group_id) do
    case Enum.find(groups, fn group -> group.id == group_id end) do
      nil -> nil
      group -> group.priority
    end
  end

  defp detect_conflicts(candidates) do
    for {{rule_a, priority_a}, index_a} <- Enum.with_index(candidates),
        {{rule_b, priority_b}, index_b} <- Enum.with_index(candidates),
        index_a < index_b,
        priority_a == priority_b,
        rule_a.action != rule_b.action,
        Matcher.overlaps?(rule_a.matcher, rule_b.matcher) do
      %Conflict{
        rule_a: rule_a.id,
        rule_b: rule_b.id,
        group_a: rule_a.group_id,
        group_b: rule_b.group_id,
        priority: priority_a,
        reason: overlap_reason(rule_a.matcher, rule_b.matcher)
      }
    end
    |> Enum.sort_by(fn c -> {c.rule_a, c.rule_b} end)
  end

  defp overlap_reason(a, b) do
    "protocols #{a.protocol}/#{b.protocol}, destinations #{inspect(a.cidr)} vs #{inspect(b.cidr)}, " <>
      "ports #{inspect(a.ports)} vs #{inspect(b.ports)} overlap; opposing actions"
  end

  defp order_candidates(candidates) do
    Enum.sort(candidates, fn {rule_a, priority_a}, {rule_b, priority_b} ->
      cond do
        priority_a != priority_b ->
          priority_a > priority_b

        Matcher.prefix_len(rule_a.matcher) != Matcher.prefix_len(rule_b.matcher) ->
          Matcher.prefix_len(rule_a.matcher) > Matcher.prefix_len(rule_b.matcher)

        Matcher.port_width(rule_a.matcher) != Matcher.port_width(rule_b.matcher) ->
          Matcher.port_width(rule_a.matcher) < Matcher.port_width(rule_b.matcher)

        true ->
          rule_a.id <= rule_b.id
      end
    end)
  end

  defp ordered_entries(ordered) do
    Enum.map(ordered, fn {rule, priority} ->
      %{rule: rule, priority: priority}
    end)
  end

  defp shadows_for(ordered, current_index, current_rule) do
    ordered
    |> Enum.drop(current_index + 1)
    |> Enum.filter(fn {lower_rule, _priority} ->
      current_rule.action != lower_rule.action and
        Matcher.overlaps?(current_rule.matcher, lower_rule.matcher)
    end)
    |> Enum.map(fn {lower_rule, _priority} -> lower_rule.id end)
  end
end
