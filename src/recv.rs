use log::{error, warn};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::net::UdpSocket;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, RecvTimeoutError},
    Arc,
};
use std::thread;
use std::time::Duration;

pub fn recv(device: String, dns_send: mpsc::Sender<Arc<Vec<u8>>>, running: Arc<AtomicBool>) {
    let interfaces = datalink::interfaces();

    let interface = match interfaces
        .iter()
        .find(|iface| iface.name == device && !iface.is_loopback())
    {
        Some(iface) => iface,
        None => {
            error!("网络接口 '{}' 未找到", device);
            return;
        }
    };

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(1000)), // 设置读取超时
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            error!("通道类型不支持");
            return;
        }
        Err(error) => {
            error!("创建数据链路通道失败: {}", error);
            return;
        }
    };

    // 创建一个通道来在线程间传递数据包
    let (packet_sender, packet_receiver) = mpsc::channel();
    let running_clone = running.clone();

    // 在单独的线程中处理数据包接收
    let capture_handle = thread::spawn(move || {
        while running_clone.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet) => {
                    // 检查是否需要停止
                    if !running_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    let packet_data = packet.to_vec();
                    if packet_sender.send(Ok(packet_data)).is_err() {
                        // 接收端已关闭，退出线程
                        break;
                    }
                }
                Err(e) => {
                    // 检查是否是超时错误（这是正常的）
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        // 超时是正常的，继续循环
                        continue;
                    }

                    if packet_sender.send(Err(e)).is_err() {
                        // 接收端已关闭，退出线程
                        break;
                    }
                    break; // 出现其他错误时退出
                }
            }
        }
        drop(rx);
    });

    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;

    // 主循环处理接收到的数据包
    while running.load(Ordering::Relaxed) {
        match packet_receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(packet_data)) => {
                consecutive_errors = 0;
                if let Some(ethernet) = EthernetPacket::new(&packet_data) {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let ipv4_data = ipv4.packet().to_vec();
                        let cloned_ipv4: Arc<Vec<u8>> = Arc::new(ipv4_data);
                        match dns_send.send(cloned_ipv4) {
                            Ok(_) => {}
                            Err(error) => {
                                warn!("发送抓到的数据包失败: {}", error);
                                break; // 如果发送失败，可能是接收端已关闭
                            }
                        }
                    }
                }
            }
            Ok(Err(error)) => {
                consecutive_errors += 1;
                warn!("读取数据链路通道时发生错误: {}", error);
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    warn!("连续错误次数过多，停止抓包");
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // 超时是正常的，继续循环检查running标志
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                // 发送端断开连接，退出
                break;
            }
        }
    }

    // 显式清理资源，确保底层网络句柄被正确释放
    drop(packet_receiver);
    drop(dns_send);

    // 等待数据包捕获线程结束
    if let Err(error) = capture_handle.join() {
        warn!("等待抓包线程结束失败: {:?}", error);
    }
}

pub fn recv_udp(socket: UdpSocket, dns_send: mpsc::Sender<Arc<Vec<u8>>>, running: Arc<AtomicBool>) {
    if let Err(error) = socket.set_read_timeout(Some(Duration::from_millis(1000))) {
        error!("设置UDP兼容接收超时失败: {}", error);
        return;
    }

    let mut buffer = vec![0u8; 4096];

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => {
                if dns_send.send(Arc::new(buffer[..len].to_vec())).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                warn!("UDP兼容接收失败: {}", error);
                break;
            }
        }
    }
}
