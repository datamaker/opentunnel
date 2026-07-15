//! Thread-safe VPN client IP address pool.
//!
//! Port of `routing/ipPool.ts`. The gateway (first usable address) is reserved.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

pub struct IpPool {
    base_ip: u32,
    netmask_bits: u32,
    max_hosts: u32,
    used: Mutex<HashSet<u32>>,
}

#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub total: u32,
    pub used: usize,
    pub available: usize,
}

impl IpPool {
    /// Create a pool for the given CIDR (e.g. `"10.8.0.0/24"`). The `.1` gateway
    /// address is reserved on construction.
    pub fn new(cidr: &str) -> Self {
        let (subnet, bits) = cidr.split_once('/').unwrap_or((cidr, "24"));
        let netmask_bits: u32 = bits.parse().unwrap_or(24);
        let base_ip = ip_to_u32(subnet);
        let max_hosts = 2u32.saturating_pow(32 - netmask_bits).saturating_sub(2);

        let mut used = HashSet::new();
        // Reserve gateway (base + 1).
        used.insert(base_ip + 1);

        IpPool {
            base_ip,
            netmask_bits,
            max_hosts,
            used: Mutex::new(used),
        }
    }

    /// Allocate the lowest free host address, or `None` if the pool is exhausted.
    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let mut used = self.used.lock().unwrap();
        for i in 2..=self.max_hosts {
            let candidate = self.base_ip + i;
            if !used.contains(&candidate) {
                used.insert(candidate);
                return Some(u32_to_ip(candidate));
            }
        }
        None
    }

    /// Return an address to the pool.
    pub fn release(&self, ip: Ipv4Addr) {
        let n = u32::from(ip);
        self.used.lock().unwrap().remove(&n);
    }

    pub fn gateway(&self) -> Ipv4Addr {
        u32_to_ip(self.base_ip + 1)
    }

    /// Subnet mask in dotted-decimal form (e.g. `255.255.255.0`).
    pub fn subnet_mask(&self) -> String {
        let mask: u32 = if self.netmask_bits == 0 {
            0
        } else {
            0xffff_ffffu32 << (32 - self.netmask_bits)
        };
        u32_to_ip(mask).to_string()
    }

    pub fn stats(&self) -> PoolStats {
        let used = self.used.lock().unwrap().len();
        PoolStats {
            total: self.max_hosts,
            used,
            available: self.max_hosts as usize - used,
        }
    }
}

fn ip_to_u32(ip: &str) -> u32 {
    ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0)
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_from_dot_two_and_reserves_gateway() {
        let pool = IpPool::new("10.8.0.0/24");
        assert_eq!(pool.gateway(), Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(pool.subnet_mask(), "255.255.255.0");

        let first = pool.allocate().unwrap();
        assert_eq!(first, Ipv4Addr::new(10, 8, 0, 2));

        let second = pool.allocate().unwrap();
        assert_eq!(second, Ipv4Addr::new(10, 8, 0, 3));

        pool.release(first);
        // Freed address is reused first.
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 8, 0, 2));
    }
}
