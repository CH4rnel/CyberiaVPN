use cyberia_transport::{DnsConfig, TransportError};

#[test]
fn accepts_a_bounded_dual_stack_resolver_policy() {
    let config = DnsConfig {
        resolvers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
    };

    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn rejects_missing_or_unbounded_resolver_policies() {
    assert!(DnsConfig { resolvers: vec![] }.validate().is_err());
    assert!(
        DnsConfig {
            resolvers: (1..=9)
                .map(|host| format!("192.0.2.{host}").parse().unwrap())
                .collect(),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn rejects_unusable_and_canonically_duplicate_resolvers() {
    for resolvers in [
        vec!["0.0.0.0".parse().unwrap()],
        vec!["ff02::1".parse().unwrap()],
        vec![
            "192.0.2.53".parse().unwrap(),
            "::ffff:192.0.2.53".parse().unwrap(),
        ],
    ] {
        assert_eq!(
            DnsConfig { resolvers }.validate(),
            Err(TransportError::InvalidConfig(
                "invalid or duplicate DNS resolver"
            ))
        );
    }
}
