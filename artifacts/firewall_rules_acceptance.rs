//! Dependency-free acceptance for device-group firewall rule priority and
//! conflict rejection.
//!
//! It compiles the *real* gateway core at
//! `rust/gateway/src/firewall_rules.rs` and asserts:
//!   1. effective rules under three group configurations match exact
//!      expectations (ordered rule ids + flow verdicts),
//!   2. conflicting configurations are rejected at dispatch instead of being
//!      silently overwritten,
//!   3. the projected payload matches the existing gateway `Filter` wire
//!      format and uses `reject_access` for fully denied destinations.
//!
//! Run via `artifacts/run-firewall-rules-acceptance.sh`, or directly:
//! `rustc --edition=2021 artifacts/firewall_rules_acceptance.rs -o /tmp/fw-acc`.

#[path = "../rust/gateway/src/firewall_rules.rs"]
mod firewall_rules;

use firewall_rules::*;
use std::net::IpAddr;
use std::str::FromStr;

fn ip(value: &str) -> IpAddr {
    IpAddr::from_str(value).expect("valid fixture IP")
}

fn ids(policy: &ResolvedPolicy) -> Vec<String> {
    policy
        .effective
        .iter()
        .map(|entry| entry.rule_id.clone())
        .collect()
}

fn verdict_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
    }
}

struct Ctx {
    failures: Vec<String>,
    config_reports: Vec<String>,
    conflict_reports: Vec<String>,
    checks: usize,
}

impl Ctx {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
            config_reports: Vec::new(),
            conflict_reports: Vec::new(),
            checks: 0,
        }
    }

    fn expect(&mut self, condition: bool, label: &str) {
        self.checks += 1;
        if condition {
            println!("  PASS  {label}");
        } else {
            println!("  FAIL  {label}");
            self.failures.push(label.to_owned());
        }
    }

    fn expect_eq<T: PartialEq + std::fmt::Debug>(&mut self, actual: &T, expected: &T, label: &str) {
        let ok = actual == expected;
        self.checks += 1;
        if ok {
            println!("  PASS  {label}");
        } else {
            println!(
                "  FAIL  {label}\n        expected: {expected:?}\n        actual:   {actual:?}"
            );
            self.failures
                .push(format!("{label} (expected {expected:?}, got {actual:?})"));
        }
    }
}

fn matcher(protocol: Protocol, cidr: Option<&str>, ports: Option<(u16, u16)>) -> Matcher {
    Matcher::new(
        protocol,
        cidr.map(|value| Cidr::parse(value).expect("valid fixture CIDR")),
        ports.map(|(start, end)| PortRange::new(start, end).expect("valid fixture ports")),
    )
}

fn rule(id: &str, group: &str, action: Action, matcher: Matcher) -> Rule {
    Rule::new(id, group, action, matcher)
}

struct VerdictExpectation {
    flow: Flow,
    expected: Action,
    label: String,
}

fn flow_json(flow: &Flow, expected: Action, actual: Action, passed: bool) -> String {
    let port = flow
        .port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"protocol":"{}","destination":"{}","port":{},"expected":"{}","actual":"{}","pass":{}}}"#,
        flow.protocol.wire_tag(),
        flow.destination,
        port,
        verdict_name(expected),
        verdict_name(actual),
        passed
    )
}

fn check_config(
    ctx: &mut Ctx,
    name: &str,
    description: &str,
    groups: &[DeviceGroup],
    rules: &[Rule],
    members: &[&str],
    expected_ids: &[&str],
    verdicts: Vec<VerdictExpectation>,
) {
    println!("\n[config] {name} — {description}");
    let member_strings: Vec<String> = members.iter().map(|m| (*m).to_owned()).collect();
    let expected: Vec<String> = expected_ids.iter().map(|id| (*id).to_owned()).collect();

    let result = resolve(groups, rules, &member_strings, Action::Deny);
    let policy = match result {
        Ok(policy) => policy,
        Err(error) => {
            ctx.expect(
                false,
                &format!("{name}: resolved without conflict ({error})"),
            );
            ctx.config_reports.push(format!(
                r#"{{"name":"{name}","pass":false,"error":"{error}"}}"#
            ));
            return;
        }
    };

    ctx.expect(true, &format!("{name}: resolves without hard conflict"));
    let actual_ids = ids(&policy);
    ctx.expect_eq(
        &actual_ids,
        &expected,
        &format!("{name}: effective rule order"),
    );

    let mut verdict_json = Vec::new();
    for verdict in verdicts {
        let actual = policy.verdict(&verdict.flow);
        let passed = actual == verdict.expected;
        ctx.expect(
            passed,
            &format!(
                "{}: {} -> {} (expected {})",
                name,
                verdict.label,
                verdict_name(actual),
                verdict_name(verdict.expected)
            ),
        );
        verdict_json.push(flow_json(&verdict.flow, verdict.expected, actual, passed));
    }

    let shadows: Vec<String> = policy
        .effective
        .iter()
        .flat_map(|entry| {
            entry
                .shadows
                .iter()
                .map(|shadow| format!(r#"{{"by":"{}","shadows":"{}"}}"#, entry.rule_id, shadow))
        })
        .collect();

    ctx.config_reports.push(format!(
        r#"{{"name":"{name}","description":"{description}","pass":{order_pass},"expected_effective_rule_ids":{expected},"actual_effective_rule_ids":{actual},"shadow_relations":[{shadows}],"verdicts":[{verdicts}]}}"#,
        order_pass = actual_ids == expected,
        expected = string_array(&expected),
        actual = string_array(&actual_ids),
        shadows = shadows.join(","),
        verdicts = verdict_json.join(",")
    ));
}

fn string_array(values: &[String]) -> String {
    let body = values
        .iter()
        .map(|value| format!(r#""{value}""#))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn check_conflict(
    ctx: &mut Ctx,
    name: &str,
    description: &str,
    request: DispatchRequest,
    expected_rule_pair: Option<(&str, &str)>,
) {
    println!("\n[conflict] {name} — {description}");
    let result = dispatch(&request);
    let rejection = match result {
        Err(rejection) => rejection,
        Ok(receipt) => {
            ctx.expect(
                false,
                &format!("{name}: dispatch must be rejected, got {receipt:?}"),
            );
            ctx.conflict_reports.push(format!(
                r#"{{"name":"{name}","pass":false,"rejected":false}}"#
            ));
            return;
        }
    };

    ctx.expect(true, &format!("{name}: dispatch rejected explicitly"));
    ctx.expect(
        rejection.message.contains("conflict"),
        &format!("{name}: error is explicit ({})", rejection.message),
    );
    ctx.expect(
        !rejection.conflicts.is_empty(),
        &format!("{name}: structured conflict details returned"),
    );

    if let Some((a, b)) = expected_rule_pair {
        let pair_found = rejection.conflicts.iter().any(|conflict| {
            (conflict.rule_a == a && conflict.rule_b == b)
                || (conflict.rule_a == b && conflict.rule_b == a)
        });
        ctx.expect(
            pair_found,
            &format!("{name}: conflict names rules `{a}`/`{b}`"),
        );
    }

    let conflict_json: Vec<String> = rejection
        .conflicts
        .iter()
        .map(|c| {
            format!(
                r#"{{"rule_a":"{}","rule_b":"{}","group_a":"{}","group_b":"{}","priority":{},"reason":"{}"}}"#,
                c.rule_a, c.rule_b, c.group_a, c.group_b, c.priority, c.reason
            )
        })
        .collect();

    ctx.conflict_reports.push(format!(
        r#"{{"name":"{name}","description":"{description}","pass":true,"rejected":true,"conflict_count":{},"conflicts":[{conflicts}]}}"#,
        rejection.conflicts.len(),
        conflicts = conflict_json.join(",")
    ));
}

fn main() {
    let report_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "artifacts/firewall-rules-acceptance.json".to_owned());

    let mut ctx = Ctx::new();

    // ------------------------------------------------------------------
    // Configuration 1: single group, specificity-ordered baseline.
    // ------------------------------------------------------------------
    let groups1 = vec![DeviceGroup::new("office", "Office", 10)];
    let rules1 = vec![
        rule(
            "allow-bastion-ssh",
            "office",
            Action::Allow,
            matcher(Protocol::Tcp, Some("10.0.0.5/32"), Some((22, 22))),
        ),
        rule(
            "allow-internal-all-tcp",
            "office",
            Action::Allow,
            matcher(Protocol::Tcp, Some("10.0.0.0/8"), Some((0, 65535))),
        ),
        rule(
            "allow-web-https",
            "office",
            Action::Allow,
            matcher(Protocol::Tcp, None, Some((443, 443))),
        ),
    ];
    check_config(
        &mut ctx,
        "single_group_specificity",
        "one device group; most-specific matcher first, default deny",
        &groups1,
        &rules1,
        &["office"],
        &[
            "allow-bastion-ssh",
            "allow-internal-all-tcp",
            "allow-web-https",
        ],
        vec![
            VerdictExpectation {
                flow: Flow::tcp(ip("10.0.0.5"), 22),
                expected: Action::Allow,
                label: "bastion ssh".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("10.1.2.3"), 8080),
                expected: Action::Allow,
                label: "internal broad tcp".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("8.8.8.8"), 443),
                expected: Action::Allow,
                label: "public https".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("8.8.8.8"), 22),
                expected: Action::Deny,
                label: "public ssh denied".into(),
            },
            VerdictExpectation {
                flow: Flow::udp(ip("8.8.8.8"), 53),
                expected: Action::Deny,
                label: "udp not granted by tcp rules".into(),
            },
        ],
    );

    // ------------------------------------------------------------------
    // Configuration 2: two priorities; higher tier wins both deny/allow.
    // ------------------------------------------------------------------
    let groups2 = vec![
        DeviceGroup::new("standard", "Standard", 10),
        DeviceGroup::new("hardened", "Hardened", 100),
    ];
    let rules2 = vec![
        rule(
            "std-allow-web",
            "standard",
            Action::Allow,
            matcher(Protocol::Tcp, None, Some((443, 443))),
        ),
        rule(
            "std-deny-ssh",
            "standard",
            Action::Deny,
            matcher(Protocol::Tcp, None, Some((22, 22))),
        ),
        rule(
            "hard-deny-web",
            "hardened",
            Action::Deny,
            matcher(Protocol::Tcp, None, Some((443, 443))),
        ),
        rule(
            "hard-allow-bastion",
            "hardened",
            Action::Allow,
            matcher(Protocol::Tcp, Some("10.0.0.5/32"), Some((22, 22))),
        ),
    ];
    check_config(
        &mut ctx,
        "tiered_priority_override",
        "hardened priority 100 overrides standard priority 10 in both directions",
        &groups2,
        &rules2,
        &["standard", "hardened"],
        &[
            "hard-allow-bastion",
            "hard-deny-web",
            "std-allow-web",
            "std-deny-ssh",
        ],
        vec![
            VerdictExpectation {
                flow: Flow::tcp(ip("1.1.1.1"), 443),
                expected: Action::Deny,
                label: "high-prio deny beats low allow".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("10.0.0.5"), 22),
                expected: Action::Allow,
                label: "high-prio allow beats low deny".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("10.0.0.6"), 22),
                expected: Action::Deny,
                label: "bastion scope excluded".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("1.1.1.1"), 80),
                expected: Action::Deny,
                label: "unlisted http default deny".into(),
            },
        ],
    );

    // Gateway compatibility projections for config 2.
    let policy2 = resolve(
        &groups2,
        &rules2,
        &["standard".to_owned(), "hardened".to_owned()],
        Action::Deny,
    )
    .expect("config 2 resolves");
    let bastion_filters = policy2.gateway_filters_json(ip("10.0.0.5"));
    ctx.expect_eq(
        &bastion_filters,
        &r#"[{"protocol":"tcp","port_range_start":22,"port_range_end":22}]"#.to_owned(),
        "gateway wire filters for bastion IP collapse to tcp/22 (high allow wins)",
    );
    let other_filters = policy2.gateway_filters(ip("10.0.0.6"));
    ctx.expect(
        other_filters.is_empty(),
        "fully denied IP projects to no allow filters (must use reject_access, not filters:[])",
    );

    let compat_request = DispatchRequest {
        gateway_id: "gw-acceptance".into(),
        client_id: "device-42".into(),
        resource_id: "res-web-ssh".into(),
        groups: groups2.clone(),
        rules: rules2.clone(),
        member_group_ids: vec!["standard".into(), "hardened".into()],
        default_action: Action::Deny,
        destinations: vec![ip("10.0.0.5"), ip("10.0.0.6")],
    };
    let receipt = dispatch(&compat_request).expect("config 2 dispatches");
    let events: Vec<&str> = receipt.destinations.iter().map(|d| d.event).collect();
    ctx.expect_eq(
        &events,
        &vec!["allow_access", "reject_access"],
        "dispatch emits allow_access for permitted IP and reject_access for denied IP",
    );
    let wire_message = &receipt.destinations[0].message;
    ctx.expect(
        wire_message.contains(r#""event":"allow_access""#)
            && wire_message.contains(r#""port_range_start":22"#)
            && wire_message.contains(r#""client_id":"device-42""#),
        "allow_access message reuses existing gateway Filter field names",
    );

    // ------------------------------------------------------------------
    // Configuration 3: three groups, merge + one cross-tier override.
    // ------------------------------------------------------------------
    let groups3 = vec![
        DeviceGroup::new("baseline", "Baseline", 0),
        DeviceGroup::new("engineering", "Engineering", 50),
        DeviceGroup::new("sre", "SRE", 80),
    ];
    let rules3 = vec![
        rule(
            "base-dns",
            "baseline",
            Action::Allow,
            matcher(Protocol::Udp, None, Some((53, 53))),
        ),
        rule(
            "base-ntp",
            "baseline",
            Action::Allow,
            matcher(Protocol::Udp, None, Some((123, 123))),
        ),
        rule(
            "eng-registry",
            "engineering",
            Action::Allow,
            matcher(Protocol::Tcp, Some("10.20.0.0/16"), Some((5000, 5000))),
        ),
        Rule::new(
            "eng-disabled-tailnet",
            "engineering",
            Action::Allow,
            matcher(Protocol::Tcp, None, Some((9999, 9999))),
        )
        .disabled(),
        rule(
            "sre-deny-registry-prod",
            "sre",
            Action::Deny,
            matcher(Protocol::Tcp, Some("10.20.1.0/24"), Some((5000, 5000))),
        ),
        rule(
            "sre-allow-ssh",
            "sre",
            Action::Allow,
            matcher(Protocol::Tcp, Some("10.0.0.0/8"), Some((22, 22))),
        ),
    ];
    check_config(
        &mut ctx,
        "three_group_merge",
        "baseline+engineering+SRE merged; SRE deny carves prod /24 out of registry allow",
        &groups3,
        &rules3,
        &["baseline", "engineering", "sre"],
        &[
            "sre-deny-registry-prod",
            "sre-allow-ssh",
            "eng-registry",
            "base-dns",
            "base-ntp",
        ],
        vec![
            VerdictExpectation {
                flow: Flow::tcp(ip("10.20.1.10"), 5000),
                expected: Action::Deny,
                label: "prod /24 registry carved out".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("10.20.2.10"), 5000),
                expected: Action::Allow,
                label: "non-prod registry still allowed".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("10.0.0.9"), 22),
                expected: Action::Allow,
                label: "sre ssh on 10/8".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("11.0.0.9"), 22),
                expected: Action::Deny,
                label: "ssh scope limited to 10/8".into(),
            },
            VerdictExpectation {
                flow: Flow::udp(ip("8.8.8.8"), 53),
                expected: Action::Allow,
                label: "baseline dns".into(),
            },
            VerdictExpectation {
                flow: Flow::tcp(ip("8.8.8.8"), 9999),
                expected: Action::Deny,
                label: "disabled rule is absent".into(),
            },
        ],
    );

    // ------------------------------------------------------------------
    // Conflict configurations: dispatch must be rejected, never last-wins.
    // ------------------------------------------------------------------
    let conflict_groups = vec![
        DeviceGroup::new("a", "Team A", 50),
        DeviceGroup::new("b", "Team B", 50),
        DeviceGroup::new("net", "Net", 10),
        DeviceGroup::new("x", "X", 20),
        DeviceGroup::new("y", "Y", 20),
    ];

    check_conflict(
        &mut ctx,
        "cross_group_equal_priority",
        "two groups share priority 50; allow/deny overlap on the database",
        DispatchRequest {
            gateway_id: "gw".into(),
            client_id: "dev".into(),
            resource_id: "res-db".into(),
            groups: conflict_groups.clone(),
            rules: vec![
                rule(
                    "allow-db",
                    "a",
                    Action::Allow,
                    matcher(Protocol::Tcp, Some("10.1.2.0/24"), Some((5432, 5432))),
                ),
                rule(
                    "deny-db",
                    "b",
                    Action::Deny,
                    matcher(Protocol::Tcp, Some("10.1.2.3/32"), Some((5432, 5432))),
                ),
            ],
            member_group_ids: vec!["a".into(), "b".into()],
            default_action: Action::Deny,
            destinations: vec![ip("10.1.2.3")],
        },
        Some(("allow-db", "deny-db")),
    );

    check_conflict(
        &mut ctx,
        "same_group_exact_opposites",
        "identical matcher with allow then deny used to collapse to the last entry",
        DispatchRequest {
            gateway_id: "gw".into(),
            client_id: "dev".into(),
            resource_id: "res-ssh".into(),
            groups: conflict_groups.clone(),
            rules: vec![
                rule(
                    "allow-ssh",
                    "net",
                    Action::Allow,
                    matcher(Protocol::Tcp, None, Some((22, 22))),
                ),
                rule(
                    "deny-ssh",
                    "net",
                    Action::Deny,
                    matcher(Protocol::Tcp, None, Some((22, 22))),
                ),
            ],
            member_group_ids: vec!["net".into()],
            default_action: Action::Deny,
            destinations: vec![ip("10.0.0.1")],
        },
        Some(("allow-ssh", "deny-ssh")),
    );

    check_conflict(
        &mut ctx,
        "overlapping_port_ranges",
        "allow tcp/1-1024 and deny tcp/22 at the same priority overlap",
        DispatchRequest {
            gateway_id: "gw".into(),
            client_id: "dev".into(),
            resource_id: "res-mgmt".into(),
            groups: conflict_groups.clone(),
            rules: vec![
                rule(
                    "allow-low-ports",
                    "x",
                    Action::Allow,
                    matcher(Protocol::Tcp, None, Some((1, 1024))),
                ),
                rule(
                    "deny-ssh",
                    "y",
                    Action::Deny,
                    matcher(Protocol::Tcp, None, Some((22, 22))),
                ),
            ],
            member_group_ids: vec!["x".into(), "y".into()],
            default_action: Action::Deny,
            destinations: vec![ip("10.0.0.1")],
        },
        Some(("allow-low-ports", "deny-ssh")),
    );

    // Control: same priority but disjoint matchers must NOT be a conflict.
    let control_groups = vec![DeviceGroup::new("ops", "Ops", 30)];
    let control_rules = vec![
        rule(
            "allow-https",
            "ops",
            Action::Allow,
            matcher(Protocol::Tcp, None, Some((443, 443))),
        ),
        rule(
            "deny-ssh",
            "ops",
            Action::Deny,
            matcher(Protocol::Tcp, None, Some((22, 22))),
        ),
    ];
    let control = resolve(
        &control_groups,
        &control_rules,
        &["ops".to_owned()],
        Action::Deny,
    );
    ctx.expect(
        control.is_ok(),
        "control: disjoint allow/deny at same priority is not a false conflict",
    );
    if let Ok(policy) = control {
        ctx.expect_eq(
            &policy.verdict(&Flow::tcp(ip("1.1.1.1"), 443)),
            &Action::Allow,
            "control: https allowed",
        );
        ctx.expect_eq(
            &policy.verdict(&Flow::tcp(ip("1.1.1.1"), 22)),
            &Action::Deny,
            "control: ssh denied",
        );
    }

    // Demonstrate the old bug mechanically: a keyed map keeps the last write.
    let mut naive_last_wins = std::collections::BTreeMap::new();
    naive_last_wins.insert("tcp/22", "allow-ssh");
    naive_last_wins.insert("tcp/22", "deny-ssh");
    let last_winner = naive_last_wins.get("tcp/22").copied();
    ctx.expect_eq(
        &last_winner,
        &Some("deny-ssh"),
        "regression premise: naive map silently keeps the last rule",
    );

    let passed = ctx.failures.is_empty();
    let status = if passed { "passed" } else { "failed" };

    let report = format!(
        r#"{{
  "feature": "device-group rule priority + conflict detection + explicit dispatch rejection",
  "status": "{status}",
  "checks_total": {checks},
  "failures": {failure_count},
  "naive_last_write_wins_winner": "{last_winner}",
  "configurations": [{configs}],
  "conflict_cases": [{conflicts}],
  "failure_labels": {failure_labels}
}}"#,
        checks = ctx.checks,
        failure_count = ctx.failures.len(),
        last_winner = last_winner.unwrap_or("null"),
        configs = ctx.config_reports.join(","),
        conflicts = ctx.conflict_reports.join(","),
        failure_labels = string_array(&ctx.failures.iter().cloned().collect::<Vec<_>>()),
    );

    if let Some(parent) = std::path::Path::new(&report_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&report_path, report).expect("write acceptance report");
    println!("\nReport written to {report_path}");

    if passed {
        println!("\nACCEPTANCE PASSED ({} checks)", ctx.checks);
    } else {
        println!(
            "\nACCEPTANCE FAILED ({} of {} checks)",
            ctx.failures.len(),
            ctx.checks
        );
        std::process::exit(1);
    }
}
