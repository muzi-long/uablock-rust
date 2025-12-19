use regex::Regex;
use std::net::IpAddr;

/// SIP 请求信息
#[derive(Debug, Clone)]
pub struct SipRequest {
    pub source_ip: IpAddr,
    pub user_agent: String,
    pub method: String,
}

/// 解析 SIP 数据包，提取 User-Agent 和源 IP
pub struct SipParser {
    user_agent_regex: Regex,
    method_regex: Regex,
}

impl SipParser {
    pub fn new() -> Self {
        Self {
            // 匹配 User-Agent 或 user-agent 字段（不区分大小写）
            user_agent_regex: Regex::new(r"(?i)(?:user-agent|User-Agent):\s*([^\r\n]+)").unwrap(),
            // 匹配 SIP 方法（如 INVITE, REGISTER, OPTIONS 等）
            method_regex: Regex::new(r"^(INVITE|REGISTER|OPTIONS|ACK|BYE|CANCEL|PRACK|UPDATE|INFO|REFER|MESSAGE|SUBSCRIBE|NOTIFY)\s").unwrap(),
        }
    }

    /// 从 UDP 数据包中解析 SIP 请求
    /// source_ip 是从网络层捕获的真实源 IP，不可伪装
    /// 只解析 SIP 内容，不信任数据包中的任何 IP 信息
    pub fn parse_udp_packet(&self, data: &[u8], source_ip: IpAddr) -> Option<SipRequest> {
        use log::info;

        // 尝试将数据解析为 UTF-8 字符串
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => {
                // 不是文本数据，不是 SIP 请求，静默返回
                return None;
            }
        };

        // 检查是否是 SIP 请求（以 SIP 方法开头）
        let method = match self.method_regex.captures(text) {
            Some(caps) => match caps.get(1) {
                Some(m) => m.as_str().to_string(),
                None => {
                    // 不是有效的 SIP 请求，静默返回
                    return None;
                }
            },
            None => {
                // 不是 SIP 请求，静默返回（不输出日志）
                return None;
            }
        };

        // 提取 User-Agent
        let user_agent = self
            .user_agent_regex
            .captures(text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // 只处理 REGISTER 和 INVITE 请求
        if method != "REGISTER" && method != "INVITE" {
            // 其他 SIP 方法不处理，静默返回
            return None;
        }

        // 创建 SipRequest 结构
        let sip_request = SipRequest {
            source_ip, // 使用从网络层捕获的真实源 IP，不信任数据包内容
            user_agent,
            method: method.clone(),
        };

        // 是 SIP REGISTER 或 INVITE 请求，输出日志
        info!(
            "收到 SIP {} 请求，来源 IP: {}（网络层真实IP），User-Agent: {}",
            sip_request.method, sip_request.source_ip, sip_request.user_agent
        );

        Some(sip_request)
    }
}

impl Default for SipParser {
    fn default() -> Self {
        Self::new()
    }
}
