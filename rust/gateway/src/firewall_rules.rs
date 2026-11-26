//! Device-group aware firewall rule resolution.
//!
//! Conflicting rules must never be collapsed into a keyed map where the last
//! entry wins: that leaves a rule visible in configuration but absent from the
//! effective policy. This module makes precedence explicit.
//!
//! * [`DeviceGroup`]s carry a numeric [`DeviceGroup::priority`] (higher value
//!   means higher precedence).
//! * Rules attached to groups at *different* priorities are resolved
//!   deterministically by precedence. A higher-priority `deny` beats a lower
//!   `allow` and vice-versa.
//! * Two opposing rules (`allow` vs `deny`) that overlap and sit at the same
//!   precedence tier are a hard [`RuleConflict`]. [`resolve`] returns every
//!   conflict instead of picking a winner, and [`dispatch`] refuses to emit a
//!   gateway payload.
//!
//! Gateway compatibility is preserved by projecting a resolved policy back
//! onto the existing `filter` wire format consumed by connlib's
//! `FilterEngine`:
//!
//! ```json
//! { "protocol": "tcp", "port_range_start": 443, "port_range_end": 443 }
//! ```
//!
//! Winning deny rules are realised by absence from the allow-list (or by
//! sending the existing `reject_access` message for a fully denied scope), so
//! an unmodified gateway keeps enforcing the result.
//!
//! The module is intentionally dependency-free (`std` only) so it can be
//! verified directly with `rustc --test` as well as compiled as part of the
//! gateway crate.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default posture for traffic that matches no rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    Allow,
    #[default]
    Deny,
}

impl Action {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" | "accept" | "permit" => Ok(Self::Allow),
            "deny" | "drop" | "reject" => Ok(Self::Deny),
            other => Err(format!("unknown rule action `{other}`")),
        }
    }

    pub const fn wire(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// L4 protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    #[default]
    Any,
}

impl Protocol {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" | "icmpv4" | "icmpv6" => Ok(Self::Icmp),
            "any" | "*" | "all" => Ok(Self::Any),
            other => Err(format!("unknown protocol `{other}`")),
        }
    }

    /// Wire tag used by the existing gateway `Filter` enum.
    pub const fn wire_tag(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Any => "any",
        }
    }

    fn intersects(self, other: Self) -> bool {
        self == Self::Any || other == Self::Any || self == other
    }
}

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self, String> {
        if start > end {
            return Err(format!("invalid port range {start}>{end}"));
        }
        Ok(Self { start, end })
    }

    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub const fn all() -> Self {
        Self {
            start: 0,
            end: u16::MAX,
        }
    }

    pub const fn start(self) -> u16 {
        self.start
    }

    pub const fn end(self) -> u16 {
        self.end
    }

    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    pub fn width(self) -> u32 {
        u32::from(self.end) - u32::from(self.start) + 1
    }
}

/// A CIDR selector (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(input: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = input
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("CIDR `{input}` is missing a /prefix"))?;
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("invalid CIDR address `{addr_part}`"))?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("invalid prefix length `{prefix_part}`"))?;
        if prefix > max_prefix {
            return Err(format!(
                "prefix /{prefix} exceeds {max_prefix} for `{input}`"
            ));
        }
        let network = mask(addr, prefix);
        Ok(Self { network, prefix })
    }

    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains(self, addr: IpAddr) -> bool {
        let masked = mask(addr, self.prefix);
        masked == self.network
    }

    /// Two CIDRs overlap if one network contains the other's (masked) network
    /// address.
    pub fn overlaps(self, other: Self) -> bool {
        match (self.network, other.network) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => return false,
        }
        self.contains(other.network) || other.contains(self.network)
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from_be_bytes(v4.octets());
            let masked = if prefix == 0 {
                0
            } else {
                let keep = 32 - u32::from(prefix);
                if keep >= 32 {
                    0
                } else {
                    bits & (u32::MAX << keep)
                }
            };
            IpAddr::V4(Ipv4Addr::from(masked.to_be_bytes()))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from_be_bytes(v6.octets());
            let masked = if prefix == 0 {
                0
            } else {
                let keep = 128 - u128::from(prefix);
                if keep >= 128 {
                    0
                } else {
                    bits & (u128::MAX << keep)
                }
            };
            IpAddr::V6(Ipv6Addr::from(masked.to_be_bytes()))
        }
    }
}

/// Traffic matcher. A `None` field means "any".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    pub protocol: Protocol,
    pub cidr: Option<Cidr>,
    pub ports: Option<PortRange>,
}

impl Default for Matcher {
    fn default() -> Self {
        Self {
            protocol: Protocol::Any,
            cidr: None,
            ports: None,
        }
    }
}

impl Matcher {
    pub fn new(protocol: Protocol, cidr: Option<Cidr>, ports: Option<PortRange>) -> Self {
        Self {
            protocol,
            cidr,
            ports,
        }
    }

    /// Whether two matchers select at least one identical flow.
    pub fn overlaps(&self, other: &Self) -> bool {
        if !self.protocol.intersects(other.protocol) {
            return false;
        }
        let cidr_overlap = match (self.cidr, other.cidr) {
            (Some(a), Some(b)) => a.overlaps(b),
            _ => true,
        };
        if !cidr_overlap {
            return false;
        }
        match (self.ports, other.ports) {
            (Some(a), Some(b)) => a.overlaps(b),
            _ => true,
        }
    }

    pub fn matches_flow(&self, flow: &Flow) -> bool {
        if !self.protocol.intersects(flow.protocol) {
            return false;
        }
        if let Some(cidr) = self.cidr {
            if !cidr.contains(flow.destination) {
                return false;
            }
        }
        if let Some(range) = self.ports {
            match flow.port {
                Some(port) if range.contains(port) => {}
                _ => return false,
            }
        }
        true
    }

    fn prefix_len(&self) -> u8 {
        self.cidr.map_or(0, Cidr::prefix)
    }

    fn port_width(&self) -> u32 {
        self.ports.map_or(u16::MAX as u32 + 1, PortRange::width)
    }
}

/// A device group with an explicit precedence. Higher `priority` wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGroup {
    pub id: String,
    pub name: String,
    pub priority: i64,
}

impl DeviceGroup {
    pub fn new(id: impl Into<String>, name: impl Into<String>, priority: i64) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            priority,
        }
    }
}

/// A firewall rule attached to exactly one [`DeviceGroup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub group_id: String,
    pub action: Action,
    pub matcher: Matcher,
    pub enabled: bool,
}

impl Rule {
    pub fn new(
        id: impl Into<String>,
        group_id: impl Into<String>,
        action: Action,
        matcher: Matcher,
    ) -> Self {
        Self {
            id: id.into(),
            group_id: group_id.into(),
            action,
            matcher,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// A single unresolved, same-precedence, opposing overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConflict {
    pub rule_a: String,
    pub rule_b: String,
    pub group_a: String,
    pub group_b: String,
    pub priority: i64,
    pub reason: String,
}

impl fmt::Display for RuleConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conflicting rules `{}` ({}, priority {}) and `{}` ({}, priority {}): {}",
            self.rule_a,
            self.group_a,
            self.priority,
            self.rule_b,
            self.group_b,
            self.priority,
            self.reason
        )
    }
}

impl Error for RuleConflict {}

/// Resolution / validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// One or more hard conflicts; this is the important one.
    Conflicts(Vec<RuleConflict>),
    InvalidRule(String),
    UnknownGroup(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflicts(conflicts) => {
                writeln!(f, "{} firewall rule conflict(s):", conflicts.len())?;
                for conflict in conflicts {
                    writeln!(f, "  - {conflict}")?;
                }
                Ok(())
            }
            Self::InvalidRule(message) => write!(f, "invalid firewall rule: {message}"),
            Self::UnknownGroup(group) => {
                write!(f, "rule references unknown device group `{group}`")
            }
        }
    }
}

impl Error for ResolveError {}

/// A concrete flow used for verdict assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub protocol: Protocol,
    pub destination: IpAddr,
    pub port: Option<u16>,
}

impl Flow {
    pub fn tcp(destination: IpAddr, port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            destination,
            port: Some(port),
        }
    }

    pub fn udp(destination: IpAddr, port: u16) -> Self {
        Self {
            protocol: Protocol::Udp,
            destination,
            port: Some(port),
        }
    }

    pub fn icmp(destination: IpAddr) -> Self {
        Self {
            protocol: Protocol::Icmp,
            destination,
            port: None,
        }
    }
}

/// A rule annotated with its resolved group precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedRule {
    pub rule: Rule,
    pub priority: i64,
}

/// Summary of one effective rule and what it overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRule {
    pub order: usize,
    pub rule_id: String,
    pub group_id: String,
    pub priority: i64,
    pub action: Action,
    pub shadows: Vec<String>,
}

/// A conflict-free, precedence-ordered policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub default_action: Action,
    pub ordered: Vec<OrderedRule>,
    pub effective: Vec<EffectiveRule>,
}

impl ResolvedPolicy {
    /// First matching rule in precedence order decides the verdict.
    pub fn verdict(&self, flow: &Flow) -> Action {
        for ordered in &self.ordered {
            if ordered.rule.matcher.matches_flow(flow) {
                return ordered.rule.action;
            }
        }
        self.default_action
    }

    /// Project the policy for one destination onto the existing gateway
    /// `Filter` wire shape. Only winning `allow` port runs are emitted;
    /// winning denies become absence. A fully denied destination therefore
    /// yields an empty vector here and must be sent `reject_access` (or no
    /// `allow_access`) rather than `filters: []` on an authorization, because
    /// connlib interprets an empty filter list as `PermitAll`.
    pub fn gateway_filters(&self, destination: IpAddr) -> Vec<GatewayFilter> {
        let mut filters = Vec::new();

        for protocol in [Protocol::Tcp, Protocol::Udp] {
            // 0 = undecided, 1 = allow, 2 = deny. First decision wins because
            // rules are already in precedence order.
            let mut decisions = [0u8; u16::MAX as usize + 1];

            for ordered in &self.ordered {
                let rule = &ordered.rule;
                if !rule.matcher.protocol.intersects(protocol) {
                    continue;
                }
                if let Some(cidr) = rule.matcher.cidr {
                    if !cidr.contains(destination) {
                        continue;
                    }
                }
                let range = rule.matcher.ports.unwrap_or_else(PortRange::all);
                let code = match rule.action {
                    Action::Allow => 1u8,
                    Action::Deny => 2u8,
                };
                for port in range.start()..=range.end() {
                    if decisions[port as usize] == 0 {
                        decisions[port as usize] = code;
                    }
                }
            }

            let default_code = match self.default_action {
                Action::Allow => 1u8,
                Action::Deny => 2u8,
            };
            for decision in decisions.iter_mut() {
                if *decision == 0 {
                    *decision = default_code;
                }
            }

            let mut port = 0u32;
            while port <= u32::from(u16::MAX) {
                if decisions[port as usize] == 1 {
                    let start = port as u16;
                    while port <= u32::from(u16::MAX) && decisions[port as usize] == 1 {
                        port += 1;
                    }
                    let end = (port - 1) as u16;
                    let range = PortRange::new(start, end).expect("run start<=end");
                    match protocol {
                        Protocol::Tcp => filters.push(GatewayFilter::Tcp(range)),
                        Protocol::Udp => filters.push(GatewayFilter::Udp(range)),
                        _ => unreachable!(),
                    }
                } else {
                    port += 1;
                }
            }
        }

        let mut icmp_decision = 0u8;
        for ordered in &self.ordered {
            let rule = &ordered.rule;
            if !rule.matcher.protocol.intersects(Protocol::Icmp) {
                continue;
            }
            if let Some(cidr) = rule.matcher.cidr {
                if !cidr.contains(destination) {
                    continue;
                }
            }
            if icmp_decision == 0 {
                icmp_decision = match rule.action {
                    Action::Allow => 1,
                    Action::Deny => 2,
                };
            }
        }
        let icmp_allowed =
            icmp_decision == 1 || (icmp_decision == 0 && self.default_action == Action::Allow);
        if icmp_allowed {
            filters.push(GatewayFilter::Icmp);
        }

        filters
    }

    /// Render [`Self::gateway_filters`] as the JSON array understood by the
    /// current gateway.
    pub fn gateway_filters_json(&self, destination: IpAddr) -> String {
        GatewayFilter::to_json_array(&self.gateway_filters(destination))
    }
}

/// Filter in the exact tagged-enum wire format of connlib `messages::Filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayFilter {
    Tcp(PortRange),
    Udp(PortRange),
    Icmp,
}

impl GatewayFilter {
    pub fn to_json(self) -> String {
        match self {
            Self::Tcp(range) => format!(
                r#"{{"protocol":"tcp","port_range_start":{},"port_range_end":{}}}"#,
                range.start(),
                range.end()
            ),
            Self::Udp(range) => format!(
                r#"{{"protocol":"udp","port_range_start":{},"port_range_end":{}}}"#,
                range.start(),
                range.end()
            ),
            Self::Icmp => r#"{"protocol":"icmp"}"#.to_owned(),
        }
    }

    pub fn to_json_array(filters: &[Self]) -> String {
        let body = filters
            .iter()
            .map(|filter| filter.to_json())
            .collect::<Vec<_>>()
            .join(",");
        format!("[{body}]")
    }
}

fn priority_of(groups: &[DeviceGroup], id: &str) -> Option<i64> {
    groups
        .iter()
        .find(|group| group.id == id)
        .map(|g| g.priority)
}

/// Resolve the effective policy for a device that belongs to
/// `member_group_ids`.
///
/// Returns [`ResolveError::Conflicts`] with *all* conflicts rather than
/// silently choosing the last inserted rule.
pub fn resolve(
    groups: &[DeviceGroup],
    rules: &[Rule],
    member_group_ids: &[String],
    default_action: Action,
) -> Result<ResolvedPolicy, ResolveError> {
    for id in member_group_ids {
        if !groups.iter().any(|group| &group.id == id) {
            return Err(ResolveError::UnknownGroup(id.clone()));
        }
    }

    let mut seen_ids = std::collections::BTreeSet::new();
    for rule in rules {
        if !seen_ids.insert(rule.id.as_str()) {
            return Err(ResolveError::InvalidRule(format!(
                "duplicate rule id `{}`; refusing to overwrite",
                rule.id
            )));
        }
        if priority_of(groups, &rule.group_id).is_none() {
            return Err(ResolveError::UnknownGroup(rule.group_id.clone()));
        }
    }

    let members: std::collections::BTreeSet<&str> =
        member_group_ids.iter().map(String::as_str).collect();

    let mut candidates: Vec<(&Rule, i64)> = rules
        .iter()
        .filter(|rule| rule.enabled && members.contains(rule.group_id.as_str()))
        .map(|rule| {
            let priority =
                priority_of(groups, &rule.group_id).expect("group existence validated above");
            (rule, priority)
        })
        .collect();

    let mut conflicts = Vec::new();
    for index in 0..candidates.len() {
        for other in (index + 1)..candidates.len() {
            let (rule_a, priority_a) = candidates[index];
            let (rule_b, priority_b) = candidates[other];
            if priority_a != priority_b {
                continue;
            }
            if rule_a.action == rule_b.action {
                continue;
            }
            if !rule_a.matcher.overlaps(&rule_b.matcher) {
                continue;
            }
            conflicts.push(RuleConflict {
                rule_a: rule_a.id.clone(),
                rule_b: rule_b.id.clone(),
                group_a: rule_a.group_id.clone(),
                group_b: rule_b.group_id.clone(),
                priority: priority_a,
                reason: overlap_reason(&rule_a.matcher, &rule_b.matcher),
            });
        }
    }

    if !conflicts.is_empty() {
        conflicts.sort_by(|a, b| (&a.rule_a, &a.rule_b).cmp(&(&b.rule_a, &b.rule_b)));
        return Err(ResolveError::Conflicts(conflicts));
    }

    candidates.sort_by(|(rule_a, priority_a), (rule_b, priority_b)| {
        priority_b
            .cmp(priority_a)
            .then_with(|| {
                rule_b
                    .matcher
                    .prefix_len()
                    .cmp(&rule_a.matcher.prefix_len())
            })
            .then_with(|| {
                rule_a
                    .matcher
                    .port_width()
                    .cmp(&rule_b.matcher.port_width())
            })
            .then_with(|| rule_a.id.cmp(&rule_b.id))
    });

    let ordered: Vec<OrderedRule> = candidates
        .iter()
        .map(|(rule, priority)| OrderedRule {
            rule: (*rule).clone(),
            priority: *priority,
        })
        .collect();

    let mut effective = Vec::with_capacity(ordered.len());
    for (index, current) in ordered.iter().enumerate() {
        let mut shadows = Vec::new();
        for lower in ordered.iter().skip(index + 1) {
            if current.rule.action != lower.rule.action
                && current.rule.matcher.overlaps(&lower.rule.matcher)
            {
                shadows.push(lower.rule.id.clone());
            }
        }
        effective.push(EffectiveRule {
            order: index + 1,
            rule_id: current.rule.id.clone(),
            group_id: current.rule.group_id.clone(),
            priority: current.priority,
            action: current.rule.action,
            shadows,
        });
    }

    Ok(ResolvedPolicy {
        default_action,
        ordered,
        effective,
    })
}

fn overlap_reason(a: &Matcher, b: &Matcher) -> String {
    let protocol = match (a.protocol, b.protocol) {
        (p, q) if p == q => p.wire_tag().to_owned(),
        _ => format!("{}/{}", a.protocol.wire_tag(), b.protocol.wire_tag()),
    };
    let destination = match (a.cidr, b.cidr) {
        (Some(x), Some(y)) => format!("{x:?} intersects {y:?}"),
        (Some(x), None) | (None, Some(x)) => format!("destination {x:?} within any"),
        (None, None) => "any destination".to_owned(),
    };
    let ports = match (a.ports, b.ports) {
        (Some(x), Some(y)) => format!(
            "ports {}-{} and {}-{} overlap",
            x.start(),
            x.end(),
            y.start(),
            y.end()
        ),
        _ => "overlapping port scope".to_owned(),
    };
    format!("{protocol} rules overlap on {destination}; {ports}; opposing actions")
}

/// Request for the explicit dispatch entry point.
#[derive(Debug, Clone)]
pub struct DispatchRequest {
    pub gateway_id: String,
    pub client_id: String,
    pub groups: Vec<DeviceGroup>,
    pub rules: Vec<Rule>,
    pub member_group_ids: Vec<String>,
    pub default_action: Action,
    /// Destinations for which to project gateway filters.
    pub destinations: Vec<IpAddr>,
    pub resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationProjection {
    pub destination: IpAddr,
    /// Existing gateway event: `allow_access` when at least one filter is
    /// permitted, otherwise `reject_access` (an empty filter list would mean
    /// `PermitAll` to connlib).
    pub event: &'static str,
    pub filters_json: String,
    /// Existing gateway message that carries the decision/filters.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReceipt {
    pub gateway_id: String,
    pub client_id: String,
    pub resource_id: String,
    pub effective_rule_ids: Vec<String>,
    pub destinations: Vec<DestinationProjection>,
}

/// The config was rejected; nothing was sent to the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRejection {
    pub message: String,
    pub conflicts: Vec<RuleConflict>,
}

impl fmt::Display for DispatchRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refusing to dispatch firewall rules: {}", self.message)
    }
}

impl Error for DispatchRejection {}

/// Validate and resolve, and only then build the gateway-compatible payload.
///
/// Conflict configurations return [`DispatchRejection`] and produce no
/// `allow_access` payload; callers must not push any rule to the gateway when
/// this returns an error.
pub fn dispatch(request: &DispatchRequest) -> Result<DispatchReceipt, DispatchRejection> {
    let policy = resolve(
        &request.groups,
        &request.rules,
        &request.member_group_ids,
        request.default_action,
    )
    .map_err(|error| match error {
        ResolveError::Conflicts(conflicts) => DispatchRejection {
            message: format!("{} conflict(s)", conflicts.len()),
            conflicts,
        },
        other => DispatchRejection {
            message: other.to_string(),
            conflicts: Vec::new(),
        },
    })?;

    let effective_rule_ids = policy
        .effective
        .iter()
        .map(|entry| entry.rule_id.clone())
        .collect();

    let mut destinations = Vec::new();
    for destination in &request.destinations {
        let filters_json = policy.gateway_filters_json(*destination);
        let has_any_filter = !policy.gateway_filters(*destination).is_empty();
        let (event, message) = if has_any_filter {
            (
                "allow_access",
                format!(
                    r#"{{"event":"allow_access","client_id":"{}","resource_id":"{}","filters":{filters_json}}}"#,
                    request.client_id, request.resource_id
                ),
            )
        } else {
            (
                "reject_access",
                format!(
                    r#"{{"event":"reject_access","client_id":"{}","resource_id":"{}"}}"#,
                    request.client_id, request.resource_id
                ),
            )
        };
        destinations.push(DestinationProjection {
            destination: *destination,
            event,
            filters_json,
            message,
        });
    }

    Ok(DispatchReceipt {
        gateway_id: request.gateway_id.clone(),
        client_id: request.client_id.clone(),
        resource_id: request.resource_id.clone(),
        effective_rule_ids,
        destinations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(value: &str) -> IpAddr {
        IpAddr::from_str(value).unwrap()
    }

    fn groups() -> Vec<DeviceGroup> {
        vec![
            DeviceGroup::new("staff", "Staff", 10),
            DeviceGroup::new("restricted", "Restricted", 100),
            DeviceGroup::new("a", "Team A", 50),
            DeviceGroup::new("b", "Team B", 50),
        ]
    }

    #[test]
    fn single_group_rules_all_apply() {
        let rules = vec![
            Rule::new(
                "web",
                "staff",
                Action::Allow,
                Matcher::new(Protocol::Tcp, None, Some(PortRange::single(443))),
            ),
            Rule::new(
                "dns",
                "staff",
                Action::Allow,
                Matcher::new(Protocol::Udp, None, Some(PortRange::single(53))),
            ),
        ];

        let policy = resolve(&groups(), &rules, &["staff".to_owned()], Action::Deny).unwrap();

        let effective_ids: Vec<&str> = policy
            .effective
            .iter()
            .map(|entry| entry.rule_id.as_str())
            .collect();
        assert_eq!(effective_ids, vec!["dns", "web"]);
        assert_eq!(
            policy.verdict(&Flow::tcp(ip("1.1.1.1"), 443)),
            Action::Allow
        );
        assert_eq!(policy.verdict(&Flow::udp(ip("1.1.1.1"), 53)), Action::Allow);
        assert_eq!(policy.verdict(&Flow::tcp(ip("1.1.1.1"), 22)), Action::Deny);
    }

    #[test]
    fn different_priorities_override_instead_of_conflict() {
        let rules = vec![
            Rule::new(
                "allow-web",
                "staff",
                Action::Allow,
                Matcher::new(Protocol::Tcp, None, Some(PortRange::single(443))),
            ),
            Rule::new(
                "deny-web",
                "restricted",
                Action::Deny,
                Matcher::new(Protocol::Tcp, None, Some(PortRange::single(443))),
            ),
        ];

        let policy = resolve(
            &groups(),
            &rules,
            &["staff".to_owned(), "restricted".to_owned()],
            Action::Deny,
        )
        .unwrap();

        assert_eq!(policy.effective[0].rule_id, "deny-web");
        assert_eq!(policy.effective[0].priority, 100);
        assert_eq!(policy.verdict(&Flow::tcp(ip("8.8.8.8"), 443)), Action::Deny);
        assert!(policy.effective[0]
            .shadows
            .contains(&"allow-web".to_owned()));
    }

    #[test]
    fn same_priority_opposing_overlap_is_rejected() {
        let rules = vec![
            Rule::new(
                "allow-db",
                "a",
                Action::Allow,
                Matcher::new(
                    Protocol::Tcp,
                    Some(Cidr::parse("10.1.2.0/24").unwrap()),
                    Some(PortRange::single(5432)),
                ),
            ),
            Rule::new(
                "deny-db",
                "b",
                Action::Deny,
                Matcher::new(
                    Protocol::Tcp,
                    Some(Cidr::parse("10.1.2.3/32").unwrap()),
                    Some(PortRange::single(5432)),
                ),
            ),
        ];

        let error = resolve(
            &groups(),
            &rules,
            &["a".to_owned(), "b".to_owned()],
            Action::Deny,
        )
        .unwrap_err();

        match error {
            ResolveError::Conflicts(conflicts) => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].rule_a, "allow-db");
                assert_eq!(conflicts[0].rule_b, "deny-db");
                assert_eq!(conflicts[0].priority, 50);
            }
            other => panic!("expected conflicts, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_refuses_conflict_and_emits_no_payload() {
        let request = DispatchRequest {
            gateway_id: "gw-1".into(),
            client_id: "dev-1".into(),
            groups: groups(),
            rules: vec![
                Rule::new(
                    "allow-ssh",
                    "a",
                    Action::Allow,
                    Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
                ),
                Rule::new(
                    "deny-ssh",
                    "b",
                    Action::Deny,
                    Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
                ),
            ],
            member_group_ids: vec!["a".into(), "b".into()],
            default_action: Action::Deny,
            destinations: vec![ip("10.0.0.1")],
            resource_id: "res-1".into(),
        };

        let rejection = dispatch(&request).unwrap_err();
        assert_eq!(rejection.conflicts.len(), 1);
        assert!(rejection.to_string().contains("refusing to dispatch"));
    }

    #[test]
    fn gateway_filters_match_existing_wire_shape() {
        let rules = vec![
            Rule::new(
                "allow-web",
                "staff",
                Action::Allow,
                Matcher::new(Protocol::Tcp, None, Some(PortRange::new(1, 443).unwrap())),
            ),
            Rule::new(
                "block-ssh",
                "restricted",
                Action::Deny,
                Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
            ),
        ];
        let policy = resolve(
            &groups(),
            &rules,
            &["staff".into(), "restricted".into()],
            Action::Deny,
        )
        .unwrap();

        let json = policy.gateway_filters_json(ip("10.0.0.9"));
        assert!(json.contains(r#""protocol":"tcp""#));
        assert!(json.contains(r#""port_range_start":1"#));
        assert!(json.contains(r#""port_range_end":21"#));
        assert!(json.contains(r#""port_range_start":23"#));
        assert!(json.contains(r#""port_range_end":443"#));
        assert!(!json.contains("\"port_range_start\":22,"));
    }
}
