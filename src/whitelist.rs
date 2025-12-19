use log::debug;

/// 白名单管理器，支持模糊匹配
pub struct Whitelist {
    patterns: Vec<String>,
}

impl Whitelist {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    /// 检查 User-Agent 是否在白名单中（支持模糊匹配）
    pub fn is_allowed(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();

        for pattern in &self.patterns {
            let pattern_lower = pattern.to_lowercase();

            // 支持模糊匹配：如果 pattern 包含在 user_agent 中，或者 user_agent 包含在 pattern 中
            if ua_lower.contains(&pattern_lower) || pattern_lower.contains(&ua_lower) {
                debug!("User-Agent '{}' 匹配白名单模式 '{}'", user_agent, pattern);
                return true;
            }
        }

        false
    }

    /// 添加白名单模式
    #[allow(dead_code)]
    pub fn add_pattern(&mut self, pattern: String) {
        self.patterns.push(pattern);
    }

    /// 获取所有模式
    #[allow(dead_code)]
    pub fn get_patterns(&self) -> &[String] {
        &self.patterns
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        // 默认白名单，包含一些常见的合法 SIP User-Agent
        Self::new(vec![
            "freeswitch".to_string(),
            "microsip".to_string(),
            "telephone".to_string(),
            "jssip".to_string(),
        ])
    }
}
