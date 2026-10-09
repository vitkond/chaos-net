use core::fmt::Debug;


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
            "Unknown" => Self::Unknown,
            _ => unreachable!("Invalid RuleType string"),
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
#[derive(Clone, Copy)]
pub struct ChaosRule {
    pub delay_ns: u64,
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