mod iptables_manager;
mod packet_capture;
mod sip_parser;
mod whitelist;

use iptables_manager::IptablesManager;
use log::{debug, error, info, warn};
use packet_capture::PacketCapture;
use sip_parser::SipParser;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use whitelist::Whitelist;

fn main() {
    // 初始化日志（默认使用 Debug 级别以便调试）
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    info!("SIP UA 封禁工具启动");

    // 检查是否有 root 权限（iptables 需要 root 权限）
    if !is_root() {
        error!("此程序需要 root 权限才能使用 iptables");
        eprintln!("请使用 sudo 运行此程序");
        std::process::exit(1);
    }

    // 配置参数
    let args: Vec<String> = std::env::args().collect();
    let interface = args
        .get(1)
        .map(|s| s.clone())
        .unwrap_or_else(|| "eth0".to_string());

    // 第二个参数是端口，默认 5060
    let block_port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5060);

    info!("使用网络接口: {}", interface);
    info!("封禁端口: {}", block_port);

    // 初始化组件
    let mut capture = match PacketCapture::open(&interface) {
        Ok(cap) => cap,
        Err(e) => {
            error!("无法打开网络接口: {}", e);
            eprintln!("可用接口: {:?}", PacketCapture::list_interfaces());
            std::process::exit(1);
        }
    };

    let parser = SipParser::new();
    let iptables = IptablesManager::new_with_port(None, Some(block_port));

    // 初始化白名单（可以从配置文件或环境变量读取）
    let whitelist = Arc::new(Mutex::new(initialize_whitelist()));

    // 用于跟踪 IP 的最后处理时间，定期清理
    let last_processed: Arc<Mutex<std::collections::HashMap<String, Instant>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    info!("开始监控 SIP 流量...");

    // 主循环
    loop {
        match capture.next_packet() {
            Ok(Some((source_ip, data))) => {
                // 尝试解析为 SIP 请求
                // 如果不是 SIP 请求，parse_udp_packet 会返回 None，不输出任何日志
                if let Some(sip_request) = parser.parse_udp_packet(&data, source_ip) {
                    // 只有解析到 SIP REGISTER 或 INVITE 请求才会到这里

                    let ip_str = sip_request.source_ip.to_string();
                    let whitelist_guard = whitelist.lock().unwrap();
                    let is_allowed = whitelist_guard.is_allowed(&sip_request.user_agent);
                    drop(whitelist_guard);

                    if is_allowed {
                        // UA 在白名单中，检查是否需要解封
                        if iptables.is_blocked(&sip_request.source_ip) {
                            info!(
                                "【解封】User-Agent: '{}', IP: {}, 原因: UA 在白名单中",
                                sip_request.user_agent, sip_request.source_ip
                            );
                            match iptables.unblock_ip(&sip_request.source_ip) {
                                Ok(_) => {
                                    info!(
                                        "【解封成功】User-Agent: '{}', IP: {}",
                                        sip_request.user_agent, sip_request.source_ip
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "【解封失败】User-Agent: '{}', IP: {}, 错误: {}",
                                        sip_request.user_agent, sip_request.source_ip, e
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "User-Agent '{}' 在白名单中，IP {} 未被封禁，无需操作",
                                sip_request.user_agent, sip_request.source_ip
                            );
                        }
                    } else {
                        // UA 不在白名单中，检查是否需要封禁
                        let is_blocked = iptables.is_blocked(&sip_request.source_ip);
                        if !is_blocked {
                            warn!(
                                "【封禁】User-Agent: '{}', IP: {}, 原因: UA 不在白名单中",
                                sip_request.user_agent, sip_request.source_ip
                            );
                            match iptables.block_ip(&sip_request.source_ip) {
                                Ok(_) => {
                                    info!(
                                        "【封禁成功】User-Agent: '{}', IP: {}",
                                        sip_request.user_agent, sip_request.source_ip
                                    );
                                    // 再次检查确认封禁是否生效
                                    if iptables.is_blocked(&sip_request.source_ip) {
                                        info!(
                                            "【确认封禁】User-Agent: '{}', IP: {} 已被成功封禁",
                                            sip_request.user_agent, sip_request.source_ip
                                        );
                                    } else {
                                        warn!(
                                            "【警告】User-Agent: '{}', IP: {} 封禁后检查状态为未封禁，可能规则未正确添加",
                                            sip_request.user_agent, sip_request.source_ip
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "【封禁失败】User-Agent: '{}', IP: {}, 错误: {}",
                                        sip_request.user_agent, sip_request.source_ip, e
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "User-Agent '{}' 不在白名单中，IP {} 已被封禁，无需重复封禁",
                                sip_request.user_agent, sip_request.source_ip
                            );
                        }
                    }

                    // 记录处理时间
                    let mut last_processed_guard = last_processed.lock().unwrap();
                    last_processed_guard.insert(ip_str, Instant::now());
                }
                // 如果不是 SIP 请求，静默忽略（不输出日志）
            }
            Ok(None) => {
                // 超时或无效数据包，继续
                // 每 1000 次超时输出一次日志，避免日志过多
                use std::sync::atomic::{AtomicU64, Ordering};
                static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);
                let count = TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if count % 1000 == 0 {
                    debug!("等待数据包中... (已等待 {} 次)", count);
                }
            }
            Err(e) => {
                error!("抓包错误: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        // 定期清理过期的处理记录（每 1000 次循环检查一次）
        static mut CLEANUP_COUNTER: u32 = 0;
        unsafe {
            CLEANUP_COUNTER += 1;
            if CLEANUP_COUNTER % 1000 == 0 {
                let mut last_processed_guard = last_processed.lock().unwrap();
                let now = Instant::now();
                last_processed_guard
                    .retain(|_, time| now.duration_since(*time) < Duration::from_secs(3600));
            }
        }
    }
}

/// 初始化白名单
fn initialize_whitelist() -> Whitelist {
    // 可以从环境变量或配置文件读取
    let patterns = if let Ok(whitelist_env) = std::env::var("SIP_UA_WHITELIST") {
        whitelist_env
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    } else {
        // 默认白名单
        vec![
            "freeswitch".to_string(),
            "microsip".to_string(),
            "telephone".to_string(),
            "jssip".to_string(),
        ]
    };

    info!("白名单模式: {:?}", patterns);
    Whitelist::new(patterns)
}

/// 检查是否有 root 权限
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        // Windows 或其他系统，可能需要不同的检查方式
        true
    }
}
