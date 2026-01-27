use log::{debug, error, info, warn};
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

/// GeoIP 查询器，用于判断 IP 所属国家
pub struct GeoIpChecker {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpChecker {
    /// 创建 GeoIP 查询器
    /// db_path: GeoLite2-Country.mmdb 数据库文件路径
    pub fn new(db_path: &str) -> Self {
        let path = Path::new(db_path);
        if !path.exists() {
            warn!("GeoIP 数据库文件不存在: {}", db_path);
            return Self { reader: None };
        }

        match Reader::open_readfile(db_path) {
            Ok(reader) => {
                info!("成功加载 GeoIP 数据库: {}", db_path);
                Self {
                    reader: Some(reader),
                }
            }
            Err(e) => {
                error!("无法加载 GeoIP 数据库 {}: {}", db_path, e);
                Self { reader: None }
            }
        }
    }

    /// 检查数据库是否可用
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    /// 获取 IP 的国家代码（如 "CN", "US" 等）
    pub fn get_country_code(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;

        match reader.lookup::<geoip2::Country>(*ip) {
            Ok(result) => {
                let country_code = result
                    .country
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string());
                debug!("IP {} 的国家代码: {:?}", ip, country_code);
                country_code
            }
            Err(e) => {
                debug!("查询 IP {} 的国家信息失败: {}", ip, e);
                None
            }
        }
    }

    /// 检查 IP 是否是中国 IP
    pub fn is_china_ip(&self, ip: &IpAddr) -> bool {
        match self.get_country_code(ip) {
            Some(code) => code == "CN",
            None => {
                // 无法确定国家时，默认不封禁（保守策略）
                debug!("无法确定 IP {} 的国家，默认视为中国 IP", ip);
                true
            }
        }
    }
}

impl Default for GeoIpChecker {
    fn default() -> Self {
        // 尝试常见的 GeoIP 数据库路径
        let common_paths = [
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            "/var/lib/GeoIP/GeoLite2-Country.mmdb",
            "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
            "./GeoLite2-Country.mmdb",
            "/etc/GeoLite2-Country.mmdb",
        ];

        for path in &common_paths {
            if Path::new(path).exists() {
                info!("在默认路径找到 GeoIP 数据库: {}", path);
                return Self::new(path);
            }
        }

        warn!("未找到 GeoIP 数据库，请指定路径或下载 GeoLite2-Country.mmdb");
        Self { reader: None }
    }
}
