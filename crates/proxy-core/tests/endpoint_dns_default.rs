//! The endpoint DNS policy a build starts with, at the call sites that dial
//! nodes. A separate test process, because the policy is global. Only names
//! this machine answers itself are resolved: the default sends those to the
//! platform resolver alone, so nothing here reaches a public resolver.

use proxy_core::dns::{EndpointDnsPolicy, EndpointDnsSpec, ParsePolicyError};
use proxy_core::transport::{
    apply_endpoint_dns, endpoint_dns, resolve_endpoint_addresses, set_endpoint_dns,
};
use proxy_core::upstream::UpstreamAddress;
use tokio::net::TcpListener;

// One test, because its steps share the process-wide policy.
#[tokio::test]
async fn the_default_policy_dials_a_local_node_and_a_configuration_can_replace_it() {
    // What the process starts with, before anything sets a policy.
    let unset = match std::env::var("ENDPOINT_DNS") {
        Ok(spec) if !spec.trim().is_empty() => spec.parse(),
        _ => Ok(EndpointDnsPolicy::default()),
    };
    assert_eq!(endpoint_dns(), unset);

    // Set rather than assumed, so an `ENDPOINT_DNS` in the environment of
    // the test run does not decide what is tested.
    set_endpoint_dns(EndpointDnsPolicy::default());
    assert_eq!(endpoint_dns(), Ok(EndpointDnsPolicy::default()));

    let addresses = resolve_endpoint_addresses("localhost").await.unwrap();
    assert!(!addresses.is_empty());
    assert!(
        addresses.iter().all(|address| address.is_loopback()),
        "{addresses:?}"
    );

    let node = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = node.local_addr().unwrap().port();
    let address = UpstreamAddress::parse(&format!("localhost:{port}")).unwrap();
    let (connected, accepted) = tokio::join!(address.connect(), node.accept());
    connected.unwrap();
    accepted.unwrap();

    // A configuration's policy replaces it, an invalid one changes nothing,
    // and a configuration without one gives the choice back to the process.
    let strict = EndpointDnsPolicy::encrypted();
    apply_endpoint_dns(Some(&strict.to_spec())).unwrap();
    assert_eq!(endpoint_dns(), Ok(strict.clone()));
    assert_eq!(
        apply_endpoint_dns(Some(&EndpointDnsSpec::Text("system,encrypted".to_owned()))),
        Err(ParsePolicyError::SystemNotLast)
    );
    assert_eq!(endpoint_dns(), Ok(strict));
    apply_endpoint_dns(None).unwrap();
    assert_eq!(endpoint_dns(), unset);
}
