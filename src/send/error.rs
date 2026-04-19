use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDogError {
    InterfaceNotFound { device: String },
    UnsupportedChannelType { interface: String },
    ChannelCreationFailed { interface: String, source: String },
    MissingDestinationMac,
    InvalidDnsServer { dns_server: String, source: String },
    SendFailed { source: String },
    MissingDestinationInterface,
    SocketCreationFailed { source: String },
    SocketCloneFailed { source: String },
    SocketLocalAddressUnavailable { source: String },
}

impl fmt::Display for SendDogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendDogError::InterfaceNotFound { device } => {
                write!(f, "未找到可用于原始发包的网络接口: {}", device)
            }
            SendDogError::UnsupportedChannelType { interface } => {
                write!(f, "网络接口 {} 返回了不支持的数据链路通道类型", interface)
            }
            SendDogError::ChannelCreationFailed { interface, source } => write!(
                f,
                "创建网络接口 {} 的数据链路通道失败: {}",
                interface, source
            ),
            SendDogError::MissingDestinationMac => write!(
                f,
                "目标MAC地址为空，禁止降级为UDP socket发送，请先完成下一跳MAC解析"
            ),
            SendDogError::InvalidDnsServer { dns_server, source } => {
                write!(
                    f,
                    "DNS服务器地址 {} 无法解析为IPv4地址: {}",
                    dns_server, source
                )
            }
            SendDogError::SendFailed { source } => write!(f, "发送原始DNS数据包失败: {}", source),
            SendDogError::MissingDestinationInterface => {
                write!(f, "未指定用于发送数据包的目标网络接口")
            }
            SendDogError::SocketCreationFailed { source } => {
                write!(f, "创建UDP兼容发送socket失败: {}", source)
            }
            SendDogError::SocketCloneFailed { source } => {
                write!(f, "复制UDP兼容socket失败: {}", source)
            }
            SendDogError::SocketLocalAddressUnavailable { source } => {
                write!(f, "读取UDP兼容socket本地地址失败: {}", source)
            }
        }
    }
}

impl Error for SendDogError {}
