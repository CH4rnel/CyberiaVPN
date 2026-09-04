use cyberia_killswitch::{KillSwitch, KillSwitchError, TrafficPolicy};

#[test]
fn enabling_blocks_traffic_until_tunnel_is_ready() {
    let mut kill_switch = KillSwitch::new(false);

    kill_switch.enable();

    assert_eq!(kill_switch.policy(), &TrafficPolicy::BlockNonTunnel);
}

#[test]
fn losing_tunnel_restores_blocking_policy() {
    let mut kill_switch = KillSwitch::new(false);
    kill_switch.enable();
    kill_switch.tunnel_established("cyberia0").unwrap();

    kill_switch.tunnel_lost();

    assert_eq!(kill_switch.policy(), &TrafficPolicy::BlockNonTunnel);
}

#[test]
fn always_on_mode_cannot_be_disabled() {
    let mut kill_switch = KillSwitch::new(true);

    let result = kill_switch.disable();

    assert_eq!(result, Err(KillSwitchError::AlwaysOn));
    assert_eq!(kill_switch.policy(), &TrafficPolicy::BlockNonTunnel);
}

#[test]
fn tunnel_cannot_bypass_a_disabled_kill_switch() {
    let mut kill_switch = KillSwitch::new(false);

    let result = kill_switch.tunnel_established("cyberia0");

    assert_eq!(result, Err(KillSwitchError::NotEnabled));
    assert_eq!(kill_switch.policy(), &TrafficPolicy::Disabled);
}

#[test]
fn rejects_unsafe_interface_name() {
    let mut kill_switch = KillSwitch::new(false);
    kill_switch.enable();

    let result = kill_switch.tunnel_established("cyberia0; flush rules");

    assert_eq!(result, Err(KillSwitchError::InvalidInterface));
    assert_eq!(kill_switch.policy(), &TrafficPolicy::BlockNonTunnel);
}
