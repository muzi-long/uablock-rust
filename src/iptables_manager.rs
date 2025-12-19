use log::{debug, error, info, warn};
use std::net::IpAddr;
use std::process::Command;

/// iptables 管理器，用于封禁和解封 IP
pub struct IptablesManager {
    chain_name: String,
    block_port: Option<u16>,
}

impl IptablesManager {
    pub fn new(chain_name: Option<String>) -> Self {
        Self::new_with_port(chain_name, None)
    }

    pub fn new_with_port(chain_name: Option<String>, block_port: Option<u16>) -> Self {
        Self {
            chain_name: chain_name.unwrap_or_else(|| "INPUT".to_string()),
            block_port,
        }
    }

    /// 检查 IP 是否已被封禁
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        // 先尝试使用 -C 检查（更快速）
        let ip_str = ip.to_string();
        let mut args: Vec<String> = vec![
            "-C".to_string(),
            self.chain_name.clone(),
            "-s".to_string(),
            ip_str.clone(),
        ];

        // 如果指定了端口，添加端口限制
        if let Some(port) = self.block_port {
            let port_str = port.to_string();
            args.extend_from_slice(&[
                "-p".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                port_str,
            ]);
        }

        args.extend_from_slice(&["-j".to_string(), "DROP".to_string()]);

        let output = Command::new("iptables").args(&args).output();

        match output {
            Ok(result) if result.status.success() => return true,
            _ => {}
        }

        // 如果 -C 检查失败，尝试列出规则并手动检查（更可靠）
        let list_output = Command::new("iptables")
            .args(["-L", &self.chain_name, "-n", "--line-numbers"])
            .output();

        match list_output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                let ip_str = ip.to_string();

                for line in output_str.lines() {
                    if line.contains(&ip_str) && line.contains("DROP") {
                        // 如果指定了端口，检查端口是否匹配
                        if let Some(port) = self.block_port {
                            // 检查端口号（数字格式：dpt:5060）
                            // 或者服务名称（sip 对应 5060）
                            let port_match = line.contains(&format!("dpt:{}", port))
                                || line.contains(&port.to_string())
                                || (port == 5060
                                    && (line.contains("dpt:sip") || line.contains("sip")));

                            if port_match {
                                debug!("在规则中找到匹配的封禁规则: {}", line);
                                return true;
                            }
                        } else {
                            // 没有指定端口，只要包含 IP 和 DROP 就认为被封禁
                            debug!("在规则中找到匹配的封禁规则: {}", line);
                            return true;
                        }
                    }
                }
                false
            }
            Err(e) => {
                debug!("检查 IP {} 封禁状态失败: {}", ip, e);
                false
            }
            _ => false,
        }
    }

    /// 封禁 IP
    pub fn block_ip(&self, ip: &IpAddr) -> Result<(), String> {
        if self.is_blocked(ip) {
            debug!("IP {} 已经被封禁", ip);
            return Ok(());
        }
        let ip_str = ip.to_string();
        let mut args: Vec<String> = vec![
            "-A".to_string(),
            self.chain_name.clone(),
            "-s".to_string(),
            ip_str.clone(),
        ];

        // 如果指定了端口，添加端口限制
        if let Some(port) = self.block_port {
            let port_str = port.to_string();
            args.extend_from_slice(&[
                "-p".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                port_str,
            ]);
        }

        args.extend_from_slice(&["-j".to_string(), "DROP".to_string()]);

        debug!("执行 iptables 命令: iptables {}", args.join(" "));
        let output = Command::new("iptables").args(&args).output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    let port_info = self
                        .block_port
                        .map(|p| format!("端口 {}", p))
                        .unwrap_or_else(|| "所有端口".to_string());
                    info!("成功封禁 IP: {} {}", ip, port_info);

                    // 验证规则是否真的被添加
                    if !self.is_blocked(ip) {
                        warn!(
                            "警告：封禁 IP {} 后，检查状态显示未封禁，可能规则未正确添加",
                            ip
                        );
                        // 列出当前规则以便调试
                        let list_output = Command::new("iptables")
                            .args(["-L", &self.chain_name, "-n", "--line-numbers"])
                            .output();
                        if let Ok(list_result) = list_output {
                            if list_result.status.success() {
                                debug!(
                                    "当前 iptables 规则:\n{}",
                                    String::from_utf8_lossy(&list_result.stdout)
                                );
                            }
                        }
                    }
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&result.stderr);
                    let stdout_msg = String::from_utf8_lossy(&result.stdout);
                    let msg = format!(
                        "封禁 IP {} 失败: stderr={}, stdout={}",
                        ip, error_msg, stdout_msg
                    );
                    error!("{}", msg);
                    Err(msg)
                }
            }
            Err(e) => {
                let msg = format!("执行 iptables 命令失败: {}", e);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    /// 解封 IP
    pub fn unblock_ip(&self, ip: &IpAddr) -> Result<(), String> {
        if !self.is_blocked(ip) {
            debug!("IP {} 未被封禁，无需解封", ip);
            return Ok(());
        }
        // 先找到规则的行号
        let output = Command::new("iptables")
            .args(["-L", &self.chain_name, "--line-numbers", "-n"])
            .output();

        let line_numbers = match output {
            Ok(result) => {
                if !result.status.success() {
                    let error_msg = String::from_utf8_lossy(&result.stderr);
                    return Err(format!("获取 iptables 规则列表失败: {}", error_msg));
                }
                String::from_utf8_lossy(&result.stdout).to_string()
            }
            Err(e) => {
                return Err(format!("执行 iptables 命令失败: {}", e));
            }
        };

        // 查找匹配的规则行号
        let target_ip = ip.to_string();
        for line in line_numbers.lines() {
            if line.contains(&target_ip) && line.contains("DROP") {
                // 如果指定了端口，检查端口是否匹配
                let port_matches = if let Some(port) = self.block_port {
                    line.contains(&port.to_string())
                } else {
                    true
                };

                if port_matches {
                    if let Some(line_num) = line.split_whitespace().next() {
                        if let Ok(num) = line_num.parse::<u32>() {
                            // 删除规则
                            let delete_output = Command::new("iptables")
                                .args(["-D", &self.chain_name, &num.to_string()])
                                .output();

                            match delete_output {
                                Ok(result) => {
                                    if result.status.success() {
                                        info!("成功解封 IP: {}", ip);
                                        return Ok(());
                                    } else {
                                        let error_msg = String::from_utf8_lossy(&result.stderr);
                                        warn!("删除规则失败: {}", error_msg);
                                    }
                                }
                                Err(e) => {
                                    warn!("执行删除命令失败: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 如果找不到规则，尝试直接删除（可能规则格式不同）
        let ip_str = ip.to_string();
        let mut delete_args: Vec<String> = vec![
            "-D".to_string(),
            self.chain_name.clone(),
            "-s".to_string(),
            ip_str,
        ];
        if let Some(port) = self.block_port {
            let port_str = port.to_string();
            delete_args.extend_from_slice(&[
                "-p".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                port_str,
            ]);
        }
        delete_args.extend_from_slice(&["-j".to_string(), "DROP".to_string()]);

        let output = Command::new("iptables").args(&delete_args).output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("成功解封 IP: {}", ip);
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&result.stderr);
                    let msg = format!("解封 IP {} 失败: {}", ip, error_msg);
                    warn!("{}", msg);
                    Err(msg)
                }
            }
            Err(e) => {
                let msg = format!("执行 iptables 命令失败: {}", e);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }
}

impl Default for IptablesManager {
    fn default() -> Self {
        Self::new(None)
    }
}
