use core::fmt::Debug;
use derive_builder::Builder;
use core::net::Ipv4Addr;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum RuleType {
    Inbound = 0,
    Outbound = 1, 
    Unknown = 2,
}

impl Debug for RuleType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inbound => write!(f, "Inbound"),
            Self::Outbound => write!(f, "Outbound"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Into<&'static str> for RuleType {
    fn into(self) -> &'static str {
        match self {
            RuleType::Inbound => "Inbound",
            RuleType::Outbound => "Outbound",
            RuleType::Unknown => "Unknown",
        }
    }
}

impl From<&str> for RuleType {
    fn from(s: &str) -> Self {
        match s {
            "Inbound" => Self::Inbound,
            "Outbound" => Self::Outbound,
            _ => Self::Unknown
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub ipv4: u32,
    pub port: u16,
    pub protocol: u8,
    pub rule_type: RuleType,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Builder)]
#[builder(no_std, build_fn(error(validation_error = false)))]
pub struct ChaosRule {
    #[builder(default = 0)]
    pub delay_ns: u64,
    #[builder(default = 0)]
    pub jitter_ns: u64,
    #[builder(default = 0)]
    pub loss_percent: u32,
    #[builder(default = 0)]
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ChaosRule {}

impl RuleKey {
    pub fn new(rule_type: RuleType, ipv4: u32, port: u16, protocol: u8) -> Self {
        Self {
            ipv4,
            port,
            protocol,
            rule_type,
        }
    }
}

impl Debug for RuleKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, 
            "RuleKey {{ ipv4: {}, port: {}, protocol: {}, rule_type: {:?} }}", 
            {
                let ip = Ipv4Addr::from(self.ipv4.to_be_bytes());
                ip
            },
            self.port, self.protocol, self.rule_type
        )
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct RuleStats {
    pub total: u64,
    pub dropped: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleStats {}