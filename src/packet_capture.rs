use log::{debug, error};
use pcap::{Active, Capture, Device};
use std::net::IpAddr;

/// 数据包捕获器
pub struct PacketCapture {
    capture: Option<Capture<Active>>,
}

impl PacketCapture {
    /// 打开网络接口进行抓包
    pub fn open(interface: &str) -> Result<Self, String> {
        let mut cap = Capture::from_device(interface)
            .map_err(|e| format!("无法打开网络接口 {}: {}", interface, e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| format!("无法开始抓包: {}", e))?;

        // 设置过滤器，只捕获 UDP 流量（SIP 通常使用 UDP）
        cap.filter("udp", true)
            .map_err(|e| format!("设置过滤器失败: {}", e))?;

        Ok(Self { capture: Some(cap) })
    }

    /// 获取下一个数据包
    pub fn next_packet(&mut self) -> Result<Option<(IpAddr, Vec<u8>)>, String> {
        let cap = self.capture.as_mut().ok_or("捕获器未初始化")?;

        match cap.next_packet() {
            Ok(packet) => {
                // pcap 返回的数据可能包含以太网头（14字节），也可能直接从 IP 层开始
                // 首先检查是否是 IP 数据包（IP 版本在第一个字节的高4位）
                let data = &packet.data;

                if data.len() < 20 {
                    // 数据包太小，静默返回
                    return Ok(None);
                }

                // 检查第一个字节，判断是否包含以太网头
                // 以太网类型 0x0800 表示 IPv4，通常在字节 12-13（16位值）
                // 如果前两个字节看起来像 MAC 地址（通常不会超过 0xFF），可能是以太网头
                let ip_start_offset = if data.len() >= 14 {
                    let ethertype = ((data[12] as u16) << 8) | (data[13] as u16);
                    if ethertype == 0x0800 {
                        // 包含以太网头，IP 头从第 14 字节开始
                        14
                    } else if (data[0] & 0xF0) == 0x40 {
                        // 第一个字节的高4位是 0x4，表示 IPv4，没有以太网头
                        0
                    } else {
                        // 尝试从第 14 字节开始（假设有以太网头）
                        14
                    }
                } else if (data[0] & 0xF0) == 0x40 {
                    // 数据包太小，但第一个字节看起来像 IPv4
                    0
                } else {
                    // 尝试从第 0 字节开始
                    0
                };

                if data.len() < ip_start_offset + 20 {
                    // 数据包太小，静默返回
                    return Ok(None);
                }

                let ip_header = &data[ip_start_offset..];

                // 验证是否是 IPv4（版本号在第一个字节的高4位）
                if (ip_header[0] & 0xF0) != 0x40 {
                    // 不是 IPv4，静默返回
                    return Ok(None);
                }

                // 源 IP 在 IP 头的字节 12-15（相对于 IP 头开始）
                let src_ip_bytes = [ip_header[12], ip_header[13], ip_header[14], ip_header[15]];
                let src_ip = IpAddr::from(src_ip_bytes);

                // IP 头长度在字节 0 的低 4 位（IHL），单位是 4 字节
                let ip_header_len = (ip_header[0] & 0x0F) as usize * 4;

                // UDP 头在 IP 头之后，UDP 头是 8 字节
                let udp_start = ip_start_offset + ip_header_len;
                let udp_data_start = udp_start + 8;

                if data.len() > udp_data_start {
                    // UDP 数据从 udp_data_start 开始
                    let udp_data = data[udp_data_start..].to_vec();
                    // 不输出日志，只在解析到 SIP 请求时才输出
                    return Ok(Some((src_ip, udp_data)));
                }

                Ok(None)
            }
            Err(pcap::Error::TimeoutExpired) => {
                // 超时是正常的，继续等待
                Ok(None)
            }
            Err(e) => {
                error!("抓包错误: {}", e);
                Err(format!("抓包错误: {}", e))
            }
        }
    }

    /// 列出所有可用的网络接口
    pub fn list_interfaces() -> Vec<String> {
        match Device::list() {
            Ok(devices) => devices.iter().map(|d| d.name.clone()).collect(),
            Err(_) => vec![],
        }
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        if self.capture.is_some() {
            debug!("关闭数据包捕获器");
        }
    }
}
