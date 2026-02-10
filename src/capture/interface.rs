use glob::Pattern;
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use std::collections::{HashMap, HashSet};

pub struct InterfaceHandler {
    patterns: Vec<String>,
}

impl InterfaceHandler {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    pub fn get_interfaces(&self) -> Vec<NetworkInterface> {
        let interfaces = datalink::interfaces();
        let explicit: HashSet<String> = self
            .patterns
            .iter()
            .filter(|p| !p.contains('*') && !p.contains('?'))
            .cloned()
            .collect();

        interfaces
            .into_iter()
            .filter(|iface| self.matches_patterns(&iface.name))
            .filter(|iface| Self::should_capture_interface(&iface.name, &explicit))
            .collect()
    }

    /// Like `get_interfaces()`, but treats "link down" as absent so callers can stop capture.
    pub fn get_up_interfaces(&self) -> Vec<NetworkInterface> {
        self.get_interfaces()
            .into_iter()
            .filter(Self::is_interface_up)
            .collect()
    }

    fn matches_patterns(&self, iface_name: &str) -> bool {
        // When dynamic discovery is enabled, it's valid for link_patterns to be empty,
        // meaning "match everything".
        if self.patterns.is_empty() {
            return true;
        }

        self.patterns.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            Pattern::new(pattern)
                .map(|compiled| compiled.matches(iface_name))
                .unwrap_or(false)
        })
    }

    pub fn should_capture_interface(name: &str, explicit_interfaces: &HashSet<String>) -> bool {
        if !name.contains('.') {
            return true;
        }

        explicit_interfaces.contains(name)
    }

    fn is_interface_up(iface: &NetworkInterface) -> bool {
        // Best-effort cross-platform: on some platforms pnet may not populate flags.
        // Treat "unknown" as up to avoid accidentally disabling capture.
        if iface.flags == 0 {
            return true;
        }

        #[cfg(unix)]
        {
            (iface.flags & (libc::IFF_UP as u32)) != 0
        }

        #[cfg(not(unix))]
        {
            // Windows/other: flags meanings aren't consistent (and libc constants may not exist).
            // Keep capturing and rely on dynamic interface disappearance for removal.
            true
        }
    }
}

#[derive(Default)]
pub struct InterfaceState {
    known: HashMap<String, NetworkInterface>,
}

pub struct InterfaceDelta {
    pub added: Vec<NetworkInterface>,
    pub removed: Vec<String>,
}

impl InterfaceState {
    pub fn diff(&mut self, next: Vec<NetworkInterface>) -> InterfaceDelta {
        let next_map: HashMap<String, NetworkInterface> = next
            .into_iter()
            .map(|iface| (iface.name.clone(), iface))
            .collect();

        let removed = self
            .known
            .keys()
            .filter(|name| !next_map.contains_key(*name))
            .cloned()
            .collect();

        let added = next_map
            .iter()
            .filter(|(name, _)| !self.known.contains_key(*name))
            .map(|(_, iface)| iface.clone())
            .collect();

        self.known = next_map;

        InterfaceDelta { added, removed }
    }
}

#[cfg(test)]
mod tests {
    use super::{InterfaceHandler, InterfaceState};
    use pnet::datalink::NetworkInterface;
    use std::collections::HashSet;

    fn fake_interface(name: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![],
            flags: 0,
        }
    }

    #[test]
    fn vlan_sub_interface_is_ignored_without_explicit_config() {
        let explicit = HashSet::new();
        assert!(!InterfaceHandler::should_capture_interface(
            "eth0.100", &explicit
        ));
        assert!(InterfaceHandler::should_capture_interface(
            "eth0", &explicit
        ));
    }

    #[test]
    fn vlan_sub_interface_can_be_enabled_explicitly() {
        let mut explicit = HashSet::new();
        explicit.insert("eth0.100".to_string());
        assert!(InterfaceHandler::should_capture_interface(
            "eth0.100", &explicit
        ));
    }

    #[test]
    fn empty_patterns_match_all() {
        let handler = InterfaceHandler::new(vec![]);
        assert!(handler.matches_patterns("eth0"));
        assert!(handler.matches_patterns("lo"));
    }

    #[test]
    fn interface_state_diff_reports_add_and_remove() {
        let mut state = InterfaceState::default();

        let first = vec![fake_interface("eth0")];
        let delta = state.diff(first);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.removed.len(), 0);

        let second = vec![fake_interface("ens33")];
        let delta = state.diff(second);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.removed, vec!["eth0".to_string()]);
    }
}
