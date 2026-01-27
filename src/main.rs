mod geoip;
mod iptables_manager;
mod packet_capture;
mod sip_parser;
mod whitelist;

use geoip::GeoIpChecker;
use iptables_manager::IptablesManager;
use log::{debug, error, info, warn};
use packet_capture::PacketCapture;
use sip_parser::SipParser;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use whitelist::Whitelist;

fn main() {
    // 先检查帮助参数（不需要 root 权限）
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage(&args[0]);
        std::process::exit(0);
    }

    // 初始化日志
    // 对本程序使用 Debug 级别，对第三方库使用 Warn 级别（避免 maxminddb 等库输出大量调试信息）
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Warn) // 第三方库默认 Warn
        .filter_module("uablock_rust", log::LevelFilter::Debug) // 本程序 Debug
        .init();

    info!("SIP UA 封禁工具启动");

    // 检查是否有 root 权限（iptables 需要 root 权限）
    if !is_root() {
        error!("此程序需要 root 权限才能使用 iptables");
        eprintln!("请使用 sudo 运行此程序");
        std::process::exit(1);
    }

    // 解析参数
    let mut interface = "eth0".to_string();
    let mut ports: Vec<u16> = vec![5060];
    let mut geoip_enabled = false;
    let mut ua_filter_enabled = false;
    let mut geoip_db_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--interface" => {
                if i + 1 < args.len() {
                    interface = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("错误: {} 需要一个参数", args[i]);
                    std::process::exit(1);
                }
            }
            "-p" | "--ports" => {
                if i + 1 < args.len() {
                    ports = args[i + 1]
                        .split(',')
                        .filter_map(|p| p.trim().parse().ok())
                        .collect();
                    i += 2;
                } else {
                    eprintln!("错误: {} 需要一个参数", args[i]);
                    std::process::exit(1);
                }
            }
            "-g" | "--geoip" => {
                geoip_enabled = true;
                // 检查下一个参数是否是数据库路径（不以 - 开头）
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    geoip_db_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-u" | "--ua" => {
                ua_filter_enabled = true;
                i += 1;
            }
            _ => {
                eprintln!("未知参数: {}", args[i]);
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
    }

    // 如果两个过滤器都没有启用，默认启用 UA 过滤
    if !geoip_enabled && !ua_filter_enabled {
        info!("未指定过滤模式，默认启用 UA 过滤");
        ua_filter_enabled = true;
    }

    // 初始化 GeoIP 检查器
    let geoip_checker: Option<GeoIpChecker> = if geoip_enabled {
        let checker = if let Some(ref db_path) = geoip_db_path {
            GeoIpChecker::new(db_path)
        } else {
            GeoIpChecker::default()
        };

        if checker.is_available() {
            info!("GeoIP 过滤已启用：非中国 IP 将被直接封禁");
            Some(checker)
        } else {
            warn!("GeoIP 过滤已请求但数据库不可用，将跳过地理位置检查");
            None
        }
    } else {
        info!("GeoIP 过滤未启用");
        None
    };

    if ua_filter_enabled {
        info!("UA 过滤已启用：UA 不在白名单中的 IP 将被封禁");
    } else {
        info!("UA 过滤未启用");
    }

    info!("使用网络接口: {}", interface);
    info!("监听端口: {:?}", ports);

    // 初始化组件
    let mut capture = match PacketCapture::open(&interface, &ports) {
        Ok(cap) => cap,
        Err(e) => {
            error!("无法打开网络接口: {}", e);
            eprintln!("可用接口: {:?}", PacketCapture::list_interfaces());
            std::process::exit(1);
        }
    };

    let parser = SipParser::new();
    // 封禁IP的所有流量，不限制端口
    let iptables = IptablesManager::new(None);

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

                    // 如果启用了 GeoIP 过滤，先检查是否是中国 IP
                    if let Some(ref geoip) = geoip_checker {
                        if !geoip.is_china_ip(&sip_request.source_ip) {
                            // 不是中国 IP，直接封禁，不检查 UA
                            let is_blocked = iptables.is_blocked(&sip_request.source_ip);
                            if !is_blocked {
                                let country = geoip
                                    .get_country_code(&sip_request.source_ip)
                                    .unwrap_or_else(|| "Unknown".to_string());
                                warn!(
                                    "【封禁】IP: {}, 国家: {}, 原因: 非中国 IP（跳过 UA 检查）",
                                    sip_request.source_ip, country
                                );
                                match iptables.block_ip(&sip_request.source_ip) {
                                    Ok(_) => {
                                        info!(
                                            "【封禁成功】IP: {}, 国家: {}",
                                            sip_request.source_ip, country
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "【封禁失败】IP: {}, 国家: {}, 错误: {}",
                                            sip_request.source_ip, country, e
                                        );
                                    }
                                }
                            } else {
                                debug!(
                                    "IP {} 是非中国 IP，已被封禁，无需重复封禁",
                                    sip_request.source_ip
                                );
                            }
                            // 记录处理时间并跳过后续 UA 检查
                            let mut last_processed_guard = last_processed.lock().unwrap();
                            last_processed_guard.insert(ip_str, Instant::now());
                            continue;
                        }
                    }

                    // 如果未启用 UA 过滤，跳过后续 UA 检查
                    if !ua_filter_enabled {
                        debug!(
                            "UA 过滤未启用，跳过 UA 检查，IP: {}, UA: '{}'",
                            sip_request.source_ip, sip_request.user_agent
                        );
                        let mut last_processed_guard = last_processed.lock().unwrap();
                        last_processed_guard.insert(ip_str, Instant::now());
                        continue;
                    }

                    // 中国 IP 或未启用 GeoIP，继续检查 UA
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
    let whitelist = if let Ok(whitelist_env) = std::env::var("SIP_UA_WHITELIST") {
        let patterns = whitelist_env
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        Whitelist::new(patterns)
    } else {
        // 使用 Default trait 的默认白名单
        Whitelist::default()
    };

    info!("白名单模式: {:?}", whitelist.get_patterns());
    whitelist
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

/// 打印使用说明
fn print_usage(program: &str) {
    eprintln!(
        "SIP UA 封禁工具 - 基于 User-Agent 和 GeoIP 的 SIP 流量过滤

用法: {} [选项]

选项:
  -i, --interface <接口>    网络接口名称 (默认: eth0)
  -p, --ports <端口列表>    监听端口，逗号分隔 (默认: 5060)
  -g, --geoip [数据库路径]  启用 GeoIP 过滤，非中国 IP 直接封禁
  -u, --ua                  启用 UA 过滤，UA 不在白名单中则封禁
  -h, --help                显示帮助信息

过滤模式:
  - 不指定 -g 和 -u: 默认启用 UA 过滤
  - 仅 -g: 仅启用 GeoIP 过滤
  - 仅 -u: 仅启用 UA 过滤
  - -g -u: 同时启用，先 GeoIP 过滤，再 UA 过滤

示例:
  {} -i eth0 -p 5060 -u                    # 仅 UA 过滤
  {} -i eth0 -p 5060 -g                    # 仅 GeoIP 过滤
  {} -i eth0 -p 5060 -g -u                 # 同时启用
  {} -i eth0 -p 5060,5080 -g /path/to/GeoLite2-Country.mmdb -u

环境变量:
  SIP_UA_WHITELIST    UA 白名单，逗号分隔 (默认: freeswitch,microsip,telephone,jssip)
  RUST_LOG            日志级别 (默认: debug)",
        program, program, program, program, program
    );
}
