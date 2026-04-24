use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static CDN_RULES_TEXT: &str = include_str!("../../data/cdn_rules.txt");
static CDN_RULES: OnceLock<Vec<CdnRule>> = OnceLock::new();
static CDN_RULE_CACHE: OnceLock<Mutex<HashMap<String, Option<CdnRuleMatch>>>> = OnceLock::new();

#[derive(Debug, PartialEq, Eq)]
struct CdnRule {
    provider: String,
    patterns: Vec<RulePattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CdnRuleMatch {
    pub provider: String,
    pub pattern: String,
    pub match_kind: RulePatternKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RulePatternKind {
    Suffix,
    Contains,
}

impl RulePatternKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RulePatternKind::Suffix => "suffix",
            RulePatternKind::Contains => "contains",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RulePattern {
    Suffix(String),
    Contains(String),
}

pub(crate) fn match_cdn_provider_by_candidate(candidate: &str) -> Option<CdnRuleMatch> {
    let normalized = normalize_candidate(candidate);
    if normalized.is_empty() {
        return None;
    }

    let cache = CDN_RULE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock() {
        if let Some(cached) = cache.get(&normalized) {
            return cached.clone();
        }
    }

    let matched = cdn_rules().iter().find_map(|rule| {
        rule.patterns.iter().find_map(|pattern| {
            pattern.matches(normalized.as_str()).then(|| CdnRuleMatch {
                provider: rule.provider.clone(),
                pattern: pattern.pattern().to_string(),
                match_kind: pattern.kind(),
            })
        })
    });

    if let Ok(mut cache) = cache.lock() {
        cache.insert(normalized, matched.clone());
    }

    matched
}

fn cdn_rules() -> &'static [CdnRule] {
    CDN_RULES.get_or_init(|| parse_cdn_rules(CDN_RULES_TEXT))
}

fn parse_cdn_rules(content: &str) -> Vec<CdnRule> {
    content.lines().filter_map(parse_cdn_rule_line).collect()
}

fn parse_cdn_rule_line(line: &str) -> Option<CdnRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut parts = trimmed
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let provider = parts.next()?;
    let patterns = parts.filter_map(parse_rule_pattern).collect::<Vec<_>>();
    if patterns.is_empty() {
        return None;
    }

    Some(CdnRule {
        provider: provider.to_string(),
        patterns,
    })
}

fn parse_rule_pattern(value: &str) -> Option<RulePattern> {
    let (match_type, pattern) = value.split_once(':')?;
    let normalized_pattern = normalize_candidate(pattern);
    if normalized_pattern.is_empty() {
        return None;
    }

    match match_type.trim().to_ascii_lowercase().as_str() {
        "suffix" => Some(RulePattern::Suffix(normalized_pattern)),
        "contains" => Some(RulePattern::Contains(normalized_pattern)),
        _ => None,
    }
}

fn normalize_candidate(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl RulePattern {
    fn matches(&self, candidate: &str) -> bool {
        match self {
            RulePattern::Suffix(pattern) => matches_domain_suffix(candidate, pattern),
            RulePattern::Contains(pattern) => candidate.contains(pattern.as_str()),
        }
    }

    fn kind(&self) -> RulePatternKind {
        match self {
            RulePattern::Suffix(_) => RulePatternKind::Suffix,
            RulePattern::Contains(_) => RulePatternKind::Contains,
        }
    }

    fn pattern(&self) -> &str {
        match self {
            RulePattern::Suffix(pattern) | RulePattern::Contains(pattern) => pattern,
        }
    }
}

fn matches_domain_suffix(candidate: &str, suffix: &str) -> bool {
    candidate == suffix
        || candidate
            .strip_suffix(suffix)
            .is_some_and(|remaining| remaining.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        match_cdn_provider_by_candidate, matches_domain_suffix, parse_cdn_rule_line,
        parse_cdn_rules, CdnRule, CdnRuleMatch, RulePattern, RulePatternKind, CDN_RULES_TEXT,
    };

    #[test]
    fn detects_provider_from_cname_value() {
        let matched = match_cdn_provider_by_candidate("static.mgtv.com.w.kunluncan.com").unwrap();
        assert_eq!(
            matched,
            CdnRuleMatch {
                provider: "ChinaCache".to_string(),
                pattern: "kunluncan.com".to_string(),
                match_kind: RulePatternKind::Suffix,
            }
        );
    }

    #[test]
    fn detects_provider_from_ptr_value() {
        let matched = match_cdn_provider_by_candidate("edge-1.example.cloudflare.net").unwrap();
        assert_eq!(matched.provider, "Cloudflare");
    }

    #[test]
    fn ignores_non_cdn_values() {
        let matched = match_cdn_provider_by_candidate("origin.internal.example.com");
        assert_eq!(matched, None);
    }

    #[test]
    fn parses_rule_line() {
        let rule =
            parse_cdn_rule_line("Cloudflare, suffix:cloudflare.net , contains:cloudflare.com")
                .unwrap();
        assert_eq!(
            rule,
            CdnRule {
                provider: "Cloudflare".to_string(),
                patterns: vec![
                    RulePattern::Suffix("cloudflare.net".to_string()),
                    RulePattern::Contains("cloudflare.com".to_string()),
                ],
            }
        );
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let rules = parse_cdn_rules(
            r#"
            # comment

            Fastly,suffix:fastly.net
            "#,
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].provider, "Fastly");
    }

    #[test]
    fn suffix_match_respects_domain_boundaries() {
        assert!(matches_domain_suffix(
            "edge.example.cloudflare.net",
            "cloudflare.net"
        ));
        assert!(matches_domain_suffix("cloudflare.net", "cloudflare.net"));
        assert!(!matches_domain_suffix(
            "notcloudflare.net.evil.com",
            "cloudflare.net"
        ));
        assert!(!matches_domain_suffix(
            "fakecloudflare.net",
            "cloudflare.net"
        ));
    }

    #[test]
    fn embedded_rules_have_no_duplicate_provider_patterns() {
        let rules = parse_cdn_rules(CDN_RULES_TEXT);
        let mut seen = HashSet::new();

        for rule in rules {
            for pattern in rule.patterns {
                let key = (
                    rule.provider.clone(),
                    pattern.kind().as_str().to_string(),
                    pattern.pattern().to_string(),
                );
                assert!(seen.insert(key));
            }
        }
    }
}
