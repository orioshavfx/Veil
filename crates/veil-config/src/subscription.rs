//! Fetching and decoding subscription lists.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::link::{decode_base64, parse_links};
use crate::model::{Profile, Subscription, SubscriptionUsage};

pub const USER_AGENT: &str = concat!("veil/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Default)]
pub struct FetchedSubscription {
    pub profiles: Vec<Profile>,
    pub usage: Option<SubscriptionUsage>,
    pub title: Option<String>,
    pub update_interval_hours: Option<u32>,
    /// Servers in the subscription that this client cannot use, with reasons.
    pub skipped: Vec<String>,
}

/// Downloads a subscription and tags every profile with its id.
pub async fn fetch(sub: &Subscription) -> Result<FetchedSubscription> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(20))
        .build()?;
    let resp = client
        .get(&sub.url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching subscription {}", sub.name))?;

    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let usage = header("subscription-userinfo").map(|h| parse_userinfo(&h));
    let title = header("profile-title").map(|t| decode_title(&t));
    let update_interval_hours = header("profile-update-interval").and_then(|v| v.trim().parse().ok());

    let body = resp.text().await?;
    let (mut profiles, skipped) = parse_body_detailed(&body);
    for p in &mut profiles {
        p.subscription_id = Some(sub.id);
    }
    Ok(FetchedSubscription { profiles, usage, title, update_interval_hours, skipped })
}

/// A subscription body is a list of links (plain or base64) or Xray JSON configs.
pub fn parse_body(body: &str) -> Vec<Profile> {
    parse_body_detailed(body).0
}

fn parse_body_detailed(body: &str) -> (Vec<Profile>, Vec<String>) {
    if crate::xray_json::looks_like_json(body)
        && let Some(parsed) = crate::xray_json::parse(body)
    {
        return (parsed.profiles, parsed.skipped);
    }
    (parse_links_body(body), Vec::new())
}

fn parse_links_body(body: &str) -> Vec<Profile> {
    let trimmed = body.trim();
    if !trimmed.contains("://")
        && let Some(text) = decode_base64(trimmed).and_then(|b| String::from_utf8(b).ok()) {
            return parse_links(&text);
        }
    parse_links(trimmed)
}

/// Parses `upload=1; download=2; total=3; expire=4`.
pub fn parse_userinfo(header: &str) -> SubscriptionUsage {
    let mut usage = SubscriptionUsage::default();
    for part in header.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        // Some panels send floats like "1.5e9".
        let v = v.trim().parse::<f64>().map(|f| f as u64).unwrap_or(0);
        match k.trim() {
            "upload" => usage.upload = v,
            "download" => usage.download = v,
            "total" => usage.total = v,
            "expire" => usage.expire = v,
            _ => {}
        }
    }
    usage
}

fn decode_title(raw: &str) -> String {
    raw.strip_prefix("base64:")
        .and_then(decode_base64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| raw.to_string())
}

pub fn is_due(sub: &Subscription) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    sub.last_updated
        .is_none_or(|t| now.saturating_sub(t) >= u64::from(sub.update_interval_hours) * 3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn base64_and_plain_bodies() {
        let list = "trojan://a@b.com:443#1\nss://YWVzLTI1Ni1nY206cHc@1.1.1.1:1#2\n";
        assert_eq!(parse_body(list).len(), 2);
        let encoded = base64::engine::general_purpose::STANDARD.encode(list);
        assert_eq!(parse_body(&encoded).len(), 2);
    }

    #[test]
    fn userinfo() {
        let u = parse_userinfo("upload=100; download=2.5e3;total=10737418240; expire=0");
        assert_eq!((u.upload, u.download, u.total, u.expire), (100, 2500, 10737418240, 0));
    }

    #[test]
    fn title() {
        assert_eq!(decode_title("base64:0JzQvtC5"), "Мой");
        assert_eq!(decode_title("Plain"), "Plain");
    }
}
