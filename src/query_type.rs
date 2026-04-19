use std::fmt;
use std::str::FromStr;

/// DNS 查询类型
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
}

impl QueryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryType::A => "A",
            QueryType::Aaaa => "AAAA",
            QueryType::Cname => "CNAME",
            QueryType::Mx => "MX",
            QueryType::Ns => "NS",
            QueryType::Txt => "TXT",
        }
    }

    pub fn to_dns_code(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
            QueryType::Mx => 15,
            QueryType::Txt => 16,
            QueryType::Aaaa => 28,
        }
    }
}

impl Default for QueryType {
    fn default() -> Self {
        QueryType::A
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QueryType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "a" => Ok(QueryType::A),
            "aaaa" => Ok(QueryType::Aaaa),
            "cname" => Ok(QueryType::Cname),
            "mx" => Ok(QueryType::Mx),
            "ns" => Ok(QueryType::Ns),
            "txt" => Ok(QueryType::Txt),
            _ => Err(format!(
                "不支持的查询类型: {}。支持的类型: a, aaaa, cname, mx, ns, txt",
                value
            )),
        }
    }
}
