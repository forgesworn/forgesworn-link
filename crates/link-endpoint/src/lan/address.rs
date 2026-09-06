use std::net::{IpAddr, SocketAddr};

use super::LanError;

/// Binding is an explicit local-network consent. No wildcard interface or
/// automatically discovered remote address is accepted.
#[derive(Clone, Copy, Debug)]
pub enum LanBinding {
    LoopbackDevelopment(SocketAddr),
    Interface(SocketAddr),
}

impl Default for LanBinding {
    fn default() -> Self {
        Self::LoopbackDevelopment(([127, 0, 0, 1], 0).into())
    }
}

#[derive(Clone)]
pub(super) struct AddressPolicy {
    pub bind: SocketAddr,
    pub(super) interface: Option<(String, IpAddr, Option<u32>)>,
}

impl AddressPolicy {
    pub fn new(binding: LanBinding) -> Result<Self, LanError> {
        match binding {
            LanBinding::LoopbackDevelopment(bind) if bind.ip().is_loopback() => Ok(Self {
                bind,
                interface: None,
            }),
            LanBinding::Interface(bind) if local_unicast(bind.ip()) => {
                let interface = if_addrs::get_if_addrs()
                    .map_err(|_| LanError::Address)?
                    .into_iter()
                    .find(|interface| interface.ip() == bind.ip() && !interface.is_p2p)
                    .ok_or(LanError::Address)?;
                let mask = match interface.addr {
                    if_addrs::IfAddr::V4(addr) => IpAddr::V4(addr.netmask),
                    if_addrs::IfAddr::V6(addr) => IpAddr::V6(addr.netmask),
                };
                let contiguous = match mask {
                    IpAddr::V4(mask) => {
                        let mask = u32::from(mask);
                        mask != 0 && mask.leading_ones() + mask.trailing_zeros() == 32
                    }
                    IpAddr::V6(mask) => {
                        let mask = u128::from(mask);
                        mask != 0 && mask.leading_ones() + mask.trailing_zeros() == 128
                    }
                };
                if !contiguous {
                    return Err(LanError::Address);
                }
                if let SocketAddr::V6(address) = bind {
                    if address.flowinfo() != 0
                        || (address.ip().is_unicast_link_local()
                            && (address.scope_id() == 0
                                || Some(address.scope_id()) != interface.index))
                    {
                        return Err(LanError::Address);
                    }
                    if !address.ip().is_unicast_link_local() && address.scope_id() != 0 {
                        return Err(LanError::Address);
                    }
                }
                Ok(Self {
                    bind,
                    interface: Some((interface.name, mask, interface.index)),
                })
            }
            _ => Err(LanError::Address),
        }
    }

    pub fn permits(&self, address: SocketAddr) -> bool {
        if address.port() == 0 || address.is_ipv4() != self.bind.is_ipv4() {
            return false;
        }
        let Some((_, mask, _)) = self.interface.as_ref() else {
            return address.ip().is_loopback();
        };
        if !local_unicast(address.ip()) {
            return false;
        }
        match (self.bind, address, mask) {
            (SocketAddr::V4(local), SocketAddr::V4(remote), IpAddr::V4(mask)) => {
                let mask = u32::from(*mask);
                let local = u32::from(*local.ip());
                let remote = u32::from(*remote.ip());
                (local & mask) == (remote & mask)
                    && remote != (local & mask)
                    && remote != (local | !mask)
            }
            (SocketAddr::V6(local), SocketAddr::V6(remote), IpAddr::V6(mask)) => {
                (u128::from(*local.ip()) & u128::from(*mask))
                    == (u128::from(*remote.ip()) & u128::from(*mask))
                    && remote.scope_id() == local.scope_id()
                    && remote.flowinfo() == 0
            }
            _ => false,
        }
    }

    pub fn still_present(&self) -> bool {
        let Some((name, mask, index)) = &self.interface else {
            return true;
        };
        if_addrs::get_if_addrs().is_ok_and(|interfaces| {
            interfaces.into_iter().any(|interface| {
                let current_mask = match interface.addr {
                    if_addrs::IfAddr::V4(ref addr) => IpAddr::V4(addr.netmask),
                    if_addrs::IfAddr::V6(ref addr) => IpAddr::V6(addr.netmask),
                };
                interface.name == *name
                    && interface.ip() == self.bind.ip()
                    && current_mask == *mask
                    && interface.index == *index
            })
        })
    }
}

fn local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}
