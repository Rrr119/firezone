//! Compatibility proof for the device-group firewall rule engine.
//!
//! The portal resolves group priorities/conflicts and projects the effective
//! policy onto the existing gateway `Filter` wire format. This test feeds the
//! projector's JSON into the *real* `messages::Filter` deserializer so the
//! compatibility claim is checked against the gateway's actual contract.

#[allow(dead_code)]
#[path = "../../../../gateway/src/firewall_rules.rs"]
mod firewall_rules;

use std::net::IpAddr;

use firewall_rules::{
    Action, DeviceGroup, Matcher, PortRange, Protocol, ResolveError, Rule, resolve,
};
use tunnel_proto::messages::{Filter, PortRange as WirePortRange};

fn ip(value: &str) -> IpAddr {
    value.parse().expect("valid fixture IP")
}

#[test]
fn projected_single_port_deserializes_as_real_tcp_filter() {
    let groups = vec![
        DeviceGroup::new("standard", "Standard", 10),
        DeviceGroup::new("hardened", "Hardened", 100),
    ];
    let rules = vec![
        Rule::new(
            "std-allow-web",
            "standard",
            Action::Allow,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(443))),
        ),
        Rule::new(
            "std-deny-ssh",
            "standard",
            Action::Deny,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
        ),
        Rule::new(
            "hard-deny-web",
            "hardened",
            Action::Deny,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(443))),
        ),
        Rule::new(
            "hard-allow-bastion",
            "hardened",
            Action::Allow,
            Matcher::new(
                Protocol::Tcp,
                Some(firewall_rules::Cidr::parse("10.0.0.5/32").unwrap()),
                Some(PortRange::single(22)),
            ),
        ),
    ];

    let policy = resolve(
        &groups,
        &rules,
        &["standard".to_owned(), "hardened".to_owned()],
        Action::Deny,
    )
    .expect("different priorities are not a conflict");

    let json = policy.gateway_filters_json(ip("10.0.0.5"));
    let filters: Vec<Filter> = serde_json::from_str(&json).expect("projected JSON must deserialize");

    assert_eq!(filters, vec![Filter::Tcp(WirePortRange::single(22))]);
}

#[test]
fn deny_subtraction_splits_an_allow_range_into_real_filters() {
    // The deny sits in a higher-priority group, so it is an intentional
    // carve-out rather than a same-priority conflict.
    let groups = vec![
        DeviceGroup::new("office", "Office", 10),
        DeviceGroup::new("sre", "SRE", 50),
    ];
    let rules = vec![
        Rule::new(
            "allow-low-ports",
            "office",
            Action::Allow,
            Matcher::new(
                Protocol::Tcp,
                None,
                Some(PortRange::new(1, 443).unwrap()),
            ),
        ),
        Rule::new(
            "deny-ssh",
            "sre",
            Action::Deny,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
        ),
    ];

    let policy = resolve(
        &groups,
        &rules,
        &["office".to_owned(), "sre".to_owned()],
        Action::Deny,
    )
    .expect("cross-priority carve-out resolves");

    let json = policy.gateway_filters_json(ip("10.0.0.1"));
    let filters: Vec<Filter> = serde_json::from_str(&json).expect("ranges must deserialize");

    assert_eq!(
        filters,
        vec![
            Filter::Tcp(WirePortRange::new(1, 21).unwrap()),
            Filter::Tcp(WirePortRange::new(23, 443).unwrap()),
        ]
    );
}

#[test]
fn icmp_and_udp_wire_shapes_deserialize() {
    for json in [
        r#"[{"protocol":"icmp"}]"#,
        r#"[{"protocol":"udp","port_range_start":53,"port_range_end":53}]"#,
    ] {
        let filters: Vec<Filter> = serde_json::from_str(json).expect("known wire shape");
        assert_eq!(filters.len(), 1);
    }
}

#[test]
fn conflict_projection_is_never_built() {
    let groups = vec![
        DeviceGroup::new("a", "A", 50),
        DeviceGroup::new("b", "B", 50),
    ];
    let rules = vec![
        Rule::new(
            "allow",
            "a",
            Action::Allow,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
        ),
        Rule::new(
            "deny",
            "b",
            Action::Deny,
            Matcher::new(Protocol::Tcp, None, Some(PortRange::single(22))),
        ),
    ];

    let error = resolve(
        &groups,
        &rules,
        &["a".to_owned(), "b".to_owned()],
        Action::Deny,
    )
    .unwrap_err();

    assert!(matches!(error, ResolveError::Conflicts(conflicts) if conflicts.len() == 1));
}
