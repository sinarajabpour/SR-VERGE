//! Subscription and share-link import.
//!
//! Turns the formats proxy providers actually ship into a Clash Meta (mihomo)
//! config:
//!
//! * V2Ray-style subscriptions: a Base64 (or plain-text) list of share links.
//! * Single or multiple share links pasted directly into the import box.
//! * Clash YAML that only carries `proxies` (no groups/rules), which would
//!   otherwise load "successfully" while routing every connection DIRECT.
//!
//! Link parsing follows mihomo's own converter (`common/convert`) so a link
//! produces the same node the core itself would build from it.

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use percent_encoding::percent_decode_str;
use serde_yaml_ng::{Mapping, Value};
use std::collections::{HashMap, HashSet};

/// Share-link schemes we can turn into a mihomo proxy.
const KNOWN_SCHEMES: &[&str] = &[
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "socks",
    "socks5",
    "socks5h",
    "wireguard",
    "wg",
];

/// Name of the auto-select group in generated configs.
pub const AUTO_GROUP: &str = "Subscription";
/// Name of the manual-select group in generated configs. User rules and the
/// Rules page templates use it as the "send through the proxy" target.
pub const MANUAL_GROUP: &str = "Manual";

const LENIENT_B64: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);
const B64_STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT_B64);
const B64_URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT_B64);

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Detect a share-link list (Base64-encoded or plain) and convert it to a
/// complete Clash Meta config.
///
/// Returns `Ok(None)` when the content contains no share links at all, so the
/// caller can fall through to normal YAML handling. Returns an error when it
/// does contain links but none of them could be parsed.
pub fn try_convert_txt_to_yaml(raw: &str) -> Result<Option<String>> {
    let text = decode_subscription_body(raw.trim().trim_start_matches('\u{feff}'));
    let links = split_share_links(&text);
    if links.is_empty() {
        return Ok(None);
    }

    let mut proxies: Vec<Mapping> = Vec::with_capacity(links.len());
    let mut first_err: Option<anyhow::Error> = None;
    for link in &links {
        match parse_proxy_uri(link) {
            Ok(node) => proxies.push(node),
            Err(e) => {
                log::warn!("[proxy_parser] skipping link: {e:#}");
                first_err.get_or_insert(e);
            }
        }
    }

    if proxies.is_empty() {
        let reason = first_err.map(|e| format!("{e:#}")).unwrap_or_default();
        bail!(
            "found {} share link(s) but none could be imported: {reason}",
            links.len()
        );
    }
    if proxies.len() < links.len() {
        log::warn!(
            "[proxy_parser] imported {} of {} links; the rest were skipped",
            proxies.len(),
            links.len()
        );
    }

    dedupe_proxy_names(&mut proxies);
    build_clash_yaml(proxies).map(Some)
}

/// Apply SR Verge's import transforms to raw remote subscription text and
/// return a config mihomo can load:
///
/// 1. Reject bodies that are clearly not a config (HTML pages, sing-box/Xray
///    JSON) with a message the user can act on.
/// 2. Convert share-link lists (Base64 or plain) to Clash Meta YAML.
/// 3. Deduplicate proxy names (mihomo rejects duplicates).
/// 4. Add proxy groups and rules to Clash YAML that only lists `proxies`.
pub fn normalize_subscription(data: &str) -> Result<String> {
    let data = data.trim_start_matches('\u{feff}');
    reject_non_config(data)?;

    if let Some(yaml) = try_convert_txt_to_yaml(data)? {
        log::info!("[profile] converted share-link subscription to Clash YAML");
        return Ok(yaml);
    }

    let mut out = data.to_owned();
    match dedupe_clash_yaml(&out) {
        Ok(Some(yaml)) => {
            log::info!("[profile] deduplicated proxy names in config");
            out = yaml;
        }
        Ok(None) => {}
        Err(e) => log::warn!("[profile] proxy name dedup failed: {e}"),
    }
    match complete_clash_yaml(&out) {
        Ok(Some(yaml)) => {
            log::info!("[profile] added default proxy groups/rules to config");
            out = yaml;
        }
        Ok(None) => {}
        Err(e) => log::warn!("[profile] completing config failed: {e}"),
    }
    Ok(out)
}

/// Deduplicate proxy names in a full Clash YAML config.
///
/// mihomo rejects any config that contains two proxies with the same name,
/// which some providers ship (the duplicate nodes are often genuinely
/// different servers that merely share a display label). The first occurrence
/// keeps its original name; later ones get a " #2", " #3" … suffix. References
/// inside `proxy-groups` are rewritten positionally so each group still points
/// at the intended nodes. `rules` are left untouched because the first
/// occurrence keeps its name, so any rule targeting it still resolves.
///
/// Returns `Ok(None)` when the input is not a parseable Clash config or has no
/// duplicate proxy names, so the caller can use the original data unchanged.
pub fn dedupe_clash_yaml(data: &str) -> Result<Option<String>> {
    let mut root: Value = match serde_yaml_ng::from_str(data) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let Some(map) = root.as_mapping_mut() else {
        return Ok(None);
    };
    let Some(proxies) = map.get_mut("proxies").and_then(|v| v.as_sequence_mut()) else {
        return Ok(None);
    };

    // For each original name, the ordered list of names assigned to its
    // successive occurrences (index 0 == the unchanged first occurrence).
    let occurrences = rename_duplicate_proxies(proxies);
    if !occurrences.values().any(|names| names.len() > 1) {
        return Ok(None);
    }

    if let Some(groups) = map.get_mut("proxy-groups").and_then(|v| v.as_sequence_mut()) {
        for group in groups.iter_mut() {
            if let Some(list) = group.get_mut("proxies").and_then(|v| v.as_sequence_mut()) {
                rewrite_group_refs(list, &occurrences);
            }
        }
    }

    let out = serde_yaml_ng::to_string(&root).context("failed to serialize deduped config")?;
    Ok(Some(out))
}

/// Add default proxy groups and/or rules to a Clash config that lacks them.
///
/// Some panels serve Clash YAML with only a `proxies` list. mihomo loads it,
/// but with no rules every connection goes DIRECT, so the profile looks
/// imported while nothing is proxied. Returns `Ok(None)` when nothing needs to
/// be added or the input is not a Clash config.
pub fn complete_clash_yaml(data: &str) -> Result<Option<String>> {
    let Ok(Value::Mapping(mut root)) = serde_yaml_ng::from_str::<Value>(data) else {
        return Ok(None);
    };

    let has_groups = non_empty_seq(root.get("proxy-groups"));
    let has_rules = non_empty_seq(root.get("rules"));
    if has_groups && has_rules {
        return Ok(None);
    }

    let proxy_names: Vec<Value> = root
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .map(|seq| seq.iter().filter_map(|p| p.get("name").cloned()).collect())
        .unwrap_or_default();
    let providers: Vec<Value> = root
        .get("proxy-providers")
        .and_then(|v| v.as_mapping())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    if proxy_names.is_empty() && providers.is_empty() {
        return Ok(None);
    }

    let target = if has_groups {
        first_group_name(&root).unwrap_or_else(|| MANUAL_GROUP.to_owned())
    } else {
        root.insert(
            "proxy-groups".into(),
            Value::Sequence(default_groups(proxy_names, &providers)),
        );
        MANUAL_GROUP.to_owned()
    };
    if !has_rules {
        root.insert("rules".into(), default_rules(&target));
        if !root.contains_key("find-process-mode") {
            root.insert("find-process-mode".into(), "always".into());
        }
    }

    let out = serde_yaml_ng::to_string(&root).context("failed to serialize completed config")?;
    Ok(Some(out))
}

/// Index of the proxy the core refused to load, taken from mihomo's `-t`
/// output (`proxy 12: vless 1.2.3.4:443 … error`).
pub fn rejected_proxy_index(core_output: &str) -> Option<usize> {
    core_output.match_indices("proxy ").find_map(|(pos, m)| {
        let rest = &core_output[pos + m.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || !rest[digits.len()..].starts_with(':') {
            return None;
        }
        digits.parse().ok()
    })
}

/// Remove the proxy at `index` and every proxy-group reference to it.
/// Returns the new config and the removed proxy's name. Fails when no usable
/// proxy would be left.
pub fn remove_proxy(data: &str, index: usize) -> Result<(String, String)> {
    let mut root: Value = serde_yaml_ng::from_str(data).context("config is not valid YAML")?;
    let map = root.as_mapping_mut().context("config is not a mapping")?;
    let has_providers = map.get("proxy-providers").is_some_and(|p| !p.is_null());
    let proxies = map
        .get_mut("proxies")
        .and_then(|v| v.as_sequence_mut())
        .context("config has no proxies")?;
    if index >= proxies.len() {
        bail!("proxy index {index} out of range");
    }
    let removed = proxies.remove(index);
    let name = removed
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or_default()
        .to_owned();
    if proxies.is_empty() && !has_providers {
        bail!("none of the subscription's servers can be used by the core");
    }

    if let Some(groups) = map.get_mut("proxy-groups").and_then(|v| v.as_sequence_mut()) {
        for group in groups.iter_mut().filter_map(Value::as_mapping_mut) {
            let uses_provider = group.get("use").is_some_and(|u| !u.is_null());
            if let Some(list) = group.get_mut("proxies").and_then(|v| v.as_sequence_mut()) {
                list.retain(|p| p.as_str() != Some(name.as_str()));
                // a group needs at least one member to load
                if list.is_empty() && !uses_provider {
                    list.push(s("DIRECT"));
                }
            }
        }
    }

    let out = serde_yaml_ng::to_string(&root).context("failed to serialize config")?;
    Ok((out, name))
}

// ---------------------------------------------------------------------------
// Body detection
// ---------------------------------------------------------------------------

fn reject_non_config(data: &str) -> Result<()> {
    let head: String = data
        .trim_start()
        .chars()
        .take(256)
        .collect::<String>()
        .to_ascii_lowercase();
    if head.starts_with("<!doctype") || head.starts_with("<html") || head.starts_with("<?xml") {
        bail!(
            "the subscription link returned a web page instead of a config \
             (the link may be wrong, expired, or blocked on this network)"
        );
    }
    if head.starts_with('{') && (data.contains("\"outbounds\"") || data.contains("\"inbounds\"")) {
        bail!(
            "this is a sing-box/Xray JSON config, which SR Verge cannot import; \
             ask your provider for a Clash/mihomo or V2Ray (Base64) subscription link"
        );
    }
    Ok(())
}

/// Return the subscription body as plain text: Base64 bodies are decoded,
/// anything else is returned unchanged.
fn decode_subscription_body(text: &str) -> String {
    if !split_share_links(text).is_empty() {
        return text.to_owned();
    }
    match b64_decode(text) {
        Some(decoded) if decoded.contains("://") => decoded,
        _ => text.to_owned(),
    }
}

/// Lower-cased scheme of `token` when it is a share link we can parse.
fn link_scheme(token: &str) -> Option<String> {
    let (scheme, _) = token.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    KNOWN_SCHEMES.contains(&scheme.as_str()).then_some(scheme)
}

/// Pull share links out of text. Links are usually one per line, but pasted
/// text often has several on one line separated by spaces; a new link starts
/// at every token that begins with a known scheme. Other tokens are glued
/// back onto the current link, so names with raw spaces survive.
fn split_share_links(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let mut current: Option<String> = None;
        for token in line.split_whitespace() {
            if link_scheme(token).is_some() {
                links.extend(current.take());
                current = Some(token.to_owned());
            } else if let Some(link) = current.as_mut() {
                link.push(' ');
                link.push_str(token);
            }
        }
        links.extend(current);
    }
    links
}

// ---------------------------------------------------------------------------
// Dispatch by scheme
// ---------------------------------------------------------------------------

fn parse_proxy_uri(line: &str) -> Result<Mapping> {
    let scheme = link_scheme(line).ok_or_else(|| anyhow!("unsupported link: {}", short(line)))?;
    let node = match scheme.as_str() {
        "vmess" => parse_vmess(line),
        "vless" => parse_vless(line),
        "trojan" => parse_trojan(line),
        "ss" => parse_ss(line),
        "ssr" => parse_ssr(line),
        "hysteria" => parse_hysteria(line),
        "hysteria2" | "hy2" => parse_hysteria2(line),
        "tuic" => parse_tuic(line),
        "anytls" => parse_anytls(line),
        "socks" | "socks5" | "socks5h" => parse_socks(line),
        "wireguard" | "wg" => parse_wireguard(line),
        _ => Err(anyhow!("unsupported scheme `{scheme}`")),
    };
    node.with_context(|| format!("invalid {scheme} link {}", short(line)))
}

/// First 48 characters of a link, for error messages (links carry secrets).
fn short(line: &str) -> String {
    let mut s: String = line.chars().take(48).collect();
    if line.chars().count() > 48 {
        s.push('…');
    }
    s
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

fn url_decode(s: &str) -> String {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_owned())
}

/// Query-string value decoding, matching Go's `url.ParseQuery` (`+` = space).
fn query_decode(s: &str) -> String {
    url_decode(&s.replace('+', " "))
}

fn b64_decode(s: &str) -> Option<String> {
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if stripped.is_empty() {
        return None;
    }
    [B64_STD, B64_URL]
        .iter()
        .find_map(|engine| engine.decode(&stripped).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn b64_decode_or_raw(s: &str) -> String {
    b64_decode(s).unwrap_or_else(|| s.to_owned())
}

/// A share link split into its parts. `user` is still percent-encoded;
/// `query` values and `fragment` are decoded.
struct Link {
    user: String,
    host: String,
    port: Option<String>,
    query: HashMap<String, String>,
    fragment: String,
}

impl Link {
    fn parse(line: &str) -> Result<Self> {
        let body = line.split_once("://").map_or(line, |(_, b)| b);
        let (body, fragment) = match body.split_once('#') {
            Some((b, f)) => (b, url_decode(f)),
            None => (body, String::new()),
        };
        let (body, query) = match body.split_once('?') {
            Some((b, q)) => (b, parse_query(q)),
            None => (body, HashMap::new()),
        };
        // authority ends at the first '/', the rest is the (unused) path
        let authority = body.split('/').next().unwrap_or_default();
        let (user, host_port) = match authority.rfind('@') {
            Some(idx) => (&authority[..idx], &authority[idx + 1..]),
            None => ("", authority),
        };
        let (host, port) = split_host_port(host_port)?;
        if host.is_empty() {
            bail!("missing server address");
        }
        Ok(Self {
            user: user.to_owned(),
            host,
            port,
            query,
            fragment: fragment.trim().to_owned(),
        })
    }

    fn q(&self, key: &str) -> &str {
        self.query.get(key).map_or("", String::as_str)
    }

    /// First non-empty value among `keys`.
    fn q_any(&self, keys: &[&str]) -> &str {
        keys.iter().map(|k| self.q(k)).find(|v| !v.is_empty()).unwrap_or("")
    }

    fn port_or(&self, default: u16) -> Result<u16> {
        match self.port.as_deref() {
            Some(p) if !p.is_empty() => parse_port(p),
            _ => Ok(default),
        }
    }

    fn name_or(&self, kind: &str, port: u16) -> String {
        if self.fragment.is_empty() {
            format!("{kind} {}:{port}", self.host)
        } else {
            self.fragment.clone()
        }
    }
}

fn parse_query(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in qs.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if !k.is_empty() {
            // like Go's Query().Get: the first occurrence wins
            map.entry(query_decode(k)).or_insert_with(|| query_decode(v));
        }
    }
    map
}

/// Split `host:port`, `[v6]:port` or a bare host. The port part is returned
/// verbatim so callers can accept port lists (`443,2000-3000`).
fn split_host_port(s: &str) -> Result<(String, Option<String>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').context("invalid IPv6 address")?;
        let port = rest[end + 1..].strip_prefix(':').map(str::to_owned);
        return Ok((rest[..end].to_owned(), port));
    }
    // more than one ':' without brackets is a bare IPv6 address
    if s.matches(':').count() > 1 {
        return Ok((s.to_owned(), None));
    }
    Ok(match s.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), Some(p.to_owned())),
        None => (s.to_owned(), None),
    })
}

fn parse_port(s: &str) -> Result<u16> {
    match s.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(anyhow!("invalid port `{s}`")),
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

fn comma_list(s: &str) -> Value {
    Value::Sequence(
        s.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| Value::String(v.to_owned()))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Node builder
// ---------------------------------------------------------------------------

/// Thin wrapper over a proxy mapping with insert helpers that skip empties.
struct Node(Mapping);

impl Node {
    fn new(name: &str, kind: &str, server: &str, port: u16) -> Self {
        let mut node = Self(Mapping::new());
        node.set("name", Value::String(name.to_owned()));
        node.set("type", Value::String(kind.to_owned()));
        node.set("server", Value::String(server.to_owned()));
        node.set("port", Value::Number(port.into()));
        node
    }

    fn set(&mut self, key: &str, value: Value) {
        self.0.insert(Value::String(key.to_owned()), value);
    }

    fn str(&mut self, key: &str, value: &str) {
        if !value.is_empty() {
            self.set(key, Value::String(value.to_owned()));
        }
    }

    fn flag(&mut self, key: &str, value: bool) {
        self.set(key, Value::Bool(value));
    }

    fn list(&mut self, key: &str, csv: &str) {
        if !csv.trim().is_empty() {
            self.set(key, comma_list(csv));
        }
    }

    fn map(&mut self, key: &str, value: Mapping) {
        if !value.is_empty() {
            self.set(key, Value::Mapping(value));
        }
    }
}

fn mapping(pairs: &[(&str, Value)]) -> Mapping {
    pairs
        .iter()
        .filter(|(_, v)| !matches!(v, Value::String(s) if s.is_empty()))
        .map(|(k, v)| (Value::String((*k).to_owned()), v.clone()))
        .collect()
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

// ---------------------------------------------------------------------------
// TLS and transport (shared by vmess / vless / trojan)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TlsParams<'a> {
    security: &'a str,
    sni: &'a str,
    host: &'a str,
    fingerprint: &'a str,
    alpn: &'a str,
    insecure: bool,
    public_key: &'a str,
    short_id: &'a str,
    pinned_cert: &'a str,
}

/// Apply TLS options. Returns whether TLS is on.
///
/// `sni_key` is `servername` for vmess/vless and `sni` for trojan. When no SNI
/// is given, the transport Host is used, as v2rayN does: CDN configs often use
/// an IP address as the server and only work with the domain as SNI.
fn apply_tls(node: &mut Node, p: &TlsParams<'_>, sni_key: &str, always_tls: bool) -> bool {
    let security = p.security.to_ascii_lowercase();
    let reality = security == "reality" || !p.public_key.is_empty();
    let tls = always_tls || security.ends_with("tls") || reality;
    if !tls {
        return false;
    }
    if !always_tls {
        node.flag("tls", true);
    }
    let sni = if p.sni.is_empty() && !reality {
        p.host.split(',').next().unwrap_or_default().trim()
    } else {
        p.sni
    };
    node.str(sni_key, sni);
    // uTLS fingerprint; mihomo's converter defaults to chrome and REALITY
    // requires one.
    node.str(
        "client-fingerprint",
        if p.fingerprint.is_empty() {
            "chrome"
        } else {
            p.fingerprint
        },
    );
    node.list("alpn", p.alpn);
    if p.insecure {
        node.flag("skip-cert-verify", true);
    }
    node.str("fingerprint", p.pinned_cert);
    if reality {
        node.map(
            "reality-opts",
            mapping(&[("public-key", s(p.public_key)), ("short-id", s(p.short_id))]),
        );
    }
    true
}

#[derive(Default)]
struct TransportParams<'a> {
    network: &'a str,
    header_type: &'a str,
    host: &'a str,
    path: &'a str,
    service_name: &'a str,
    mode: &'a str,
    early_data: &'a str,
    early_data_header: &'a str,
}

/// Split `?ed=2048` (WebSocket early data) off a path.
fn take_early_data(path: &str) -> (String, Option<u32>) {
    let Some((base, qs)) = path.split_once('?') else {
        return (path.to_owned(), None);
    };
    let mut ed = None;
    let rest: Vec<&str> = qs
        .split('&')
        .filter(|kv| match kv.strip_prefix("ed=") {
            Some(v) => {
                ed = v.parse().ok();
                ed.is_none()
            }
            None => !kv.is_empty(),
        })
        .collect();
    let path = if rest.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", rest.join("&"))
    };
    (path, ed)
}

fn apply_transport(node: &mut Node, p: &TransportParams<'_>) -> Result<()> {
    let mut network = p.network.trim().to_ascii_lowercase();
    if (network.is_empty() || network == "tcp" || network == "raw") && p.header_type.eq_ignore_ascii_case("http") {
        network = "http-obfs".into();
    }
    let host = p.host.split(',').next().unwrap_or_default().trim();
    match network.as_str() {
        "" | "tcp" | "raw" | "none" => {}
        "http-obfs" => {
            node.str("network", "http");
            let mut opts = mapping(&[("path", Value::Sequence(vec![s(or_root(p.path))]))]);
            if !host.is_empty() {
                opts.insert(
                    s("headers"),
                    Value::Mapping(mapping(&[("Host", Value::Sequence(vec![s(host)]))])),
                );
            }
            node.map("http-opts", opts);
        }
        "h2" | "http" => {
            node.str("network", "h2");
            let mut opts = mapping(&[("path", s(or_root(p.path)))]);
            if !host.is_empty() {
                opts.insert(s("host"), Value::Sequence(vec![s(host)]));
            }
            node.map("h2-opts", opts);
        }
        "ws" | "websocket" | "httpupgrade" => apply_ws(node, p, host, network == "httpupgrade"),
        "grpc" | "gun" => {
            node.str("network", "grpc");
            node.map("grpc-opts", mapping(&[("grpc-service-name", s(p.service_name))]));
        }
        "xhttp" | "splithttp" => {
            node.str("network", "xhttp");
            node.map(
                "xhttp-opts",
                mapping(&[("path", s(p.path)), ("host", s(host)), ("mode", s(p.mode))]),
            );
        }
        other => bail!("transport `{other}` is not supported by the mihomo core"),
    }
    Ok(())
}

fn apply_ws(node: &mut Node, p: &TransportParams<'_>, host: &str, http_upgrade: bool) {
    node.str("network", "ws");
    let (path, path_ed) = take_early_data(p.path);
    let early_data = p.early_data.parse::<u32>().ok().or(path_ed);
    let mut opts = mapping(&[("path", s(or_root(&path)))]);
    if !host.is_empty() {
        opts.insert(s("headers"), Value::Mapping(mapping(&[("Host", s(host))])));
    }
    if http_upgrade {
        opts.insert(s("v2ray-http-upgrade"), Value::Bool(true));
        if early_data.is_some() {
            opts.insert(s("v2ray-http-upgrade-fast-open"), Value::Bool(true));
        }
    } else if let Some(ed) = early_data {
        opts.insert(s("max-early-data"), Value::Number(ed.into()));
        let header = if p.early_data_header.is_empty() {
            "Sec-WebSocket-Protocol"
        } else {
            p.early_data_header
        };
        opts.insert(s("early-data-header-name"), s(header));
    }
    node.map("ws-opts", opts);
}

const fn or_root(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

// ---------------------------------------------------------------------------
// VMess / VLESS
// ---------------------------------------------------------------------------

/// Read a v2rayN JSON field that may be a string or a number.
fn json_str(v: &serde_json::Value, key: &str) -> String {
    match &v[key] {
        serde_json::Value::String(s) => s.trim().to_owned(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn parse_vmess(line: &str) -> Result<Mapping> {
    let body = line.split_once("://").map_or(line, |(_, b)| b);
    let encoded = body.split(['#', '?']).next().unwrap_or_default();
    match b64_decode(encoded) {
        Some(text) if text.trim_start().starts_with('{') => parse_vmess_v2rayn(&text),
        Some(text) if text.contains('@') => parse_vmess_shadowrocket(&text, line),
        // Xray "VMessAEAD" share link: vmess://uuid@host:port?...
        _ => parse_v_share(line, "vmess"),
    }
}

/// v2rayN format: `vmess://` + Base64(JSON).
fn parse_vmess_v2rayn(text: &str) -> Result<Mapping> {
    let v: serde_json::Value = serde_json::from_str(text).context("vmess JSON is malformed")?;
    let server = json_str(&v, "add");
    if server.is_empty() {
        bail!("missing server address");
    }
    let port = parse_port(&json_str(&v, "port"))?;
    let name = Some(json_str(&v, "ps"))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("VMess {server}:{port}"));

    let mut node = Node::new(&name, "vmess", &server, port);
    node.str("uuid", &json_str(&v, "id"));
    node.set(
        "alterId",
        Value::Number(json_str(&v, "aid").parse::<u64>().unwrap_or(0).into()),
    );
    let cipher = json_str(&v, "scy");
    node.str("cipher", if cipher.is_empty() { "auto" } else { &cipher });
    node.flag("udp", true);

    let host = json_str(&v, "host");
    let path = json_str(&v, "path");
    let security = json_str(&v, "tls");
    let tls = TlsParams {
        security: &security,
        sni: &json_str(&v, "sni"),
        host: &host,
        fingerprint: &json_str(&v, "fp"),
        alpn: &json_str(&v, "alpn"),
        insecure: parse_bool(&json_str(&v, "allowInsecure")) || parse_bool(&json_str(&v, "insecure")),
        ..TlsParams::default()
    };
    if !apply_tls(&mut node, &tls, "servername", false) {
        node.flag("tls", false);
    }

    let network = json_str(&v, "net");
    let header_type = json_str(&v, "type");
    apply_transport(
        &mut node,
        &TransportParams {
            network: &network,
            header_type: &header_type,
            host: &host,
            path: &path,
            service_name: &path,
            mode: &header_type,
            ..TransportParams::default()
        },
    )?;
    Ok(node.0)
}

/// Shadowrocket format: `vmess://` + Base64(`cipher:uuid@host:port`) + `?params`.
fn parse_vmess_shadowrocket(text: &str, line: &str) -> Result<Mapping> {
    let (userinfo, host_port) = text.rsplit_once('@').context("missing '@'")?;
    let (cipher, uuid) = userinfo.split_once(':').unwrap_or(("auto", userinfo));
    let (server, port) = split_host_port(host_port.trim())?;
    let port = parse_port(port.as_deref().unwrap_or_default())?;
    let link = Link::parse(line).ok();
    let q = |k: &str| link.as_ref().map_or("", |l| l.q(k)).to_owned();
    let name = Some(q("remarks")).filter(|n| !n.is_empty()).unwrap_or_else(|| {
        link.as_ref()
            .map(|l| l.fragment.clone())
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| format!("VMess {server}:{port}"))
    });

    let mut node = Node::new(&name, "vmess", &server, port);
    node.str("uuid", uuid);
    node.set(
        "alterId",
        Value::Number(q("alterId").parse::<u64>().unwrap_or(0).into()),
    );
    node.str("cipher", if cipher.is_empty() { "auto" } else { cipher });
    node.flag("udp", true);
    let host = q("obfsParam");
    let tls_on = if parse_bool(&q("tls")) { "tls" } else { "" };
    apply_tls(
        &mut node,
        &TlsParams {
            security: tls_on,
            sni: &q("peer"),
            host: &host,
            insecure: parse_bool(&q("allowInsecure")),
            ..TlsParams::default()
        },
        "servername",
        false,
    );
    let network = match q("obfs").as_str() {
        "websocket" => "ws".to_owned(),
        other => other.to_owned(),
    };
    let path = q("path");
    apply_transport(
        &mut node,
        &TransportParams {
            network: &network,
            host: &host,
            path: &path,
            service_name: &path,
            ..TransportParams::default()
        },
    )?;
    Ok(node.0)
}

fn parse_vless(line: &str) -> Result<Mapping> {
    parse_v_share(line, "vless")
}

/// Xray share-link standard used by VLESS and VMessAEAD links:
/// `scheme://uuid@host:port?type=..&security=..#name`
fn parse_v_share(line: &str, kind: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(443)?;
    let label = if kind == "vless" { "VLESS" } else { "VMess" };
    let mut node = Node::new(&link.name_or(label, port), kind, &link.host, port);
    let uuid = url_decode(&link.user);
    if uuid.is_empty() {
        bail!("missing uuid");
    }
    node.str("uuid", &uuid);
    node.flag("udp", true);

    if kind == "vmess" {
        node.set("alterId", Value::Number(0.into()));
        let cipher = link.q("encryption");
        node.str("cipher", if cipher.is_empty() { "auto" } else { cipher });
    } else {
        node.str("flow", &link.q("flow").to_ascii_lowercase());
        let encryption = link.q("encryption");
        if !encryption.is_empty() && encryption != "none" {
            node.str("encryption", encryption);
        }
    }
    match link.q("packetEncoding") {
        "none" => {}
        "packet" => node.flag("packet-addr", true),
        _ => node.flag("xudp", true),
    }

    let host = link.q("host");
    apply_tls(&mut node, &share_tls(&link, host), "servername", false);
    apply_transport(&mut node, &share_transport(&link, host))?;
    Ok(node.0)
}

fn share_tls<'a>(link: &'a Link, host: &'a str) -> TlsParams<'a> {
    TlsParams {
        security: link.q("security"),
        sni: link.q_any(&["sni", "peer"]),
        host,
        fingerprint: link.q("fp"),
        alpn: link.q("alpn"),
        insecure: parse_bool(link.q_any(&["allowInsecure", "insecure", "allow_insecure"])),
        public_key: link.q("pbk"),
        short_id: link.q("sid"),
        pinned_cert: link.q("pcs"),
    }
}

fn share_transport<'a>(link: &'a Link, host: &'a str) -> TransportParams<'a> {
    TransportParams {
        network: link.q("type"),
        header_type: link.q("headerType"),
        host,
        path: link.q("path"),
        service_name: link.q_any(&["serviceName", "path"]),
        mode: link.q("mode"),
        early_data: link.q("ed"),
        early_data_header: link.q("eh"),
    }
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------

fn parse_trojan(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(443)?;
    let mut node = Node::new(&link.name_or("Trojan", port), "trojan", &link.host, port);
    let password = url_decode(&link.user);
    if password.is_empty() {
        bail!("missing password");
    }
    node.str("password", &password);
    node.flag("udp", true);

    let host = link.q("host");
    apply_tls(&mut node, &share_tls(&link, host), "sni", true);
    apply_transport(&mut node, &share_transport(&link, host))?;
    Ok(node.0)
}

// ---------------------------------------------------------------------------
// Shadowsocks
// ---------------------------------------------------------------------------

fn parse_ss(line: &str) -> Result<Mapping> {
    let body = line.split_once("://").map_or(line, |(_, b)| b);
    let (body, fragment) = match body.split_once('#') {
        Some((b, f)) => (b, url_decode(f).trim().to_owned()),
        None => (body, String::new()),
    };
    let (main, query) = match body.split_once('?') {
        Some((m, q)) => (m, parse_query(q)),
        None => (body, HashMap::new()),
    };

    // SIP002 has a plain host after '@'; the legacy form Base64-encodes
    // `method:password@host:port` as a whole.
    let plain = if main.contains('@') {
        main.to_owned()
    } else {
        b64_decode(main.trim_end_matches('/')).context("legacy ss link is not valid Base64")?
    };
    let at = plain.rfind('@').context("missing '@'")?;
    let host_port = plain[at + 1..].split('/').next().unwrap_or_default();
    let (server, port) = split_host_port(host_port)?;
    let port = parse_port(port.as_deref().unwrap_or_default())?;
    if server.is_empty() {
        bail!("missing server address");
    }
    let (cipher, password) = ss_user_info(&plain[..at])?;

    let name = if fragment.is_empty() {
        format!("SS {server}:{port}")
    } else {
        fragment
    };
    let mut node = Node::new(&name, "ss", &server, port);
    node.str("cipher", &cipher.to_ascii_lowercase());
    node.str("password", &password);
    node.flag("udp", true);
    let get = |k: &str| query.get(k).map_or("", String::as_str);
    if get("udp-over-tcp") == "true" || get("uot") == "1" {
        node.flag("udp-over-tcp", true);
    }
    apply_ss_plugin(&mut node, get("plugin"));
    Ok(node.0)
}

/// `method:password`, either percent-encoded (SIP002 for 2022 ciphers) or
/// Base64-encoded.
fn ss_user_info(raw: &str) -> Result<(String, String)> {
    let decoded = url_decode(raw);
    let text = if decoded.contains(':') {
        decoded
    } else {
        b64_decode(&decoded).context("user info is not valid Base64")?
    };
    let (cipher, password) = text.split_once(':').context("user info must be method:password")?;
    if cipher.is_empty() {
        bail!("missing cipher");
    }
    Ok((cipher.trim().to_owned(), password.to_owned()))
}

/// SIP003 plugin string: `name;key=value;flag`.
fn apply_ss_plugin(node: &mut Node, plugin: &str) {
    let mut parts = plugin.split(';');
    let name = parts.next().unwrap_or_default().trim();
    if name.is_empty() {
        return;
    }
    let mut opts: HashMap<&str, &str> = HashMap::new();
    for part in parts {
        let (k, v) = part.split_once('=').unwrap_or((part, "true"));
        opts.insert(k.trim(), v.trim());
    }
    let get = |k: &str| opts.get(k).copied().unwrap_or("");

    if name.contains("obfs") {
        node.str("plugin", "obfs");
        let mode = if get("obfs").is_empty() { "http" } else { get("obfs") };
        node.map(
            "plugin-opts",
            mapping(&[("mode", s(mode)), ("host", s(get("obfs-host")))]),
        );
    } else if name.contains("v2ray-plugin") {
        node.str("plugin", "v2ray-plugin");
        let mode = [get("mode"), get("obfs")]
            .into_iter()
            .find(|m| !m.is_empty())
            .unwrap_or("websocket");
        let host = if get("host").is_empty() {
            get("obfs-host")
        } else {
            get("host")
        };
        let mut plugin_opts = mapping(&[("mode", s(mode)), ("host", s(host)), ("path", s(get("path")))]);
        if opts.contains_key("tls") {
            plugin_opts.insert(s("tls"), Value::Bool(true));
        }
        if opts.contains_key("mux") {
            plugin_opts.insert(s("mux"), Value::Bool(parse_bool(get("mux"))));
        }
        node.map("plugin-opts", plugin_opts);
    } else {
        log::warn!("[proxy_parser] ss plugin `{name}` is not supported, importing without it");
    }
}

// ---------------------------------------------------------------------------
// ShadowsocksR
// ---------------------------------------------------------------------------

/// `ssr://` + Base64(`host:port:protocol:method:obfs:b64pass/?params`).
fn parse_ssr(line: &str) -> Result<Mapping> {
    let body = line.split_once("://").map_or(line, |(_, b)| b);
    let text = b64_decode(body).context("ssr link is not valid Base64")?;
    let (main, params) = text.split_once("/?").unwrap_or((text.as_str(), ""));
    let main = main.trim_end_matches('/');

    // host may be IPv6 and contain ':', so peel fields off the right.
    let fields: Vec<&str> = main.rsplitn(6, ':').collect();
    let [password, obfs, cipher, protocol, port, host] = fields[..] else {
        bail!("expected host:port:protocol:method:obfs:password");
    };
    let server = host.trim_matches(['[', ']']);
    let port = parse_port(port)?;
    let params = parse_query(params);
    let get = |k: &str| params.get(k).map_or("", String::as_str);
    let b64 = |k: &str| b64_decode_or_raw(get(k)).trim().to_owned();

    let remarks = b64("remarks");
    let name = if remarks.is_empty() {
        format!("SSR {server}:{port}")
    } else {
        remarks
    };
    let mut node = Node::new(&name, "ssr", server, port);
    node.str("cipher", cipher);
    node.str("password", &b64_decode_or_raw(password));
    node.str("protocol", protocol);
    node.str("obfs", obfs);
    node.str("protocol-param", &b64("protoparam"));
    node.str("obfs-param", &b64("obfsparam"));
    node.flag("udp", true);
    Ok(node.0)
}

// ---------------------------------------------------------------------------
// Hysteria / Hysteria2 / TUIC / AnyTLS / SOCKS / WireGuard
// ---------------------------------------------------------------------------

fn parse_hysteria(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(443)?;
    let mut node = Node::new(&link.name_or("Hysteria", port), "hysteria", &link.host, port);
    node.str("auth-str", link.q_any(&["auth", "auth_str"]));
    node.str("sni", link.q_any(&["peer", "sni"]));
    node.str("obfs", link.q("obfs"));
    node.str("protocol", link.q("protocol"));
    node.list("alpn", link.q("alpn"));
    // mihomo refuses a hysteria node without bandwidth; use conservative
    // defaults when the link leaves them out.
    let up = link.q_any(&["up", "upmbps"]);
    let down = link.q_any(&["down", "downmbps"]);
    node.str("up", if up.is_empty() { "10" } else { up });
    node.str("down", if down.is_empty() { "50" } else { down });
    if parse_bool(link.q("insecure")) {
        node.flag("skip-cert-verify", true);
    }
    Ok(node.0)
}

fn parse_hysteria2(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    // port may be a hop list: `443,20000-30000` or `20000-30000`
    let port_spec = link.port.clone().unwrap_or_default();
    let first = port_spec.split([',', '-']).next().unwrap_or_default();
    let port = if first.is_empty() { 443 } else { parse_port(first)? };
    let mut node = Node::new(&link.name_or("Hysteria2", port), "hysteria2", &link.host, port);

    let password = url_decode(&link.user);
    node.str("password", if password.is_empty() { link.q("auth") } else { &password });
    if port_spec.contains([',', '-']) {
        node.str("ports", &port_spec);
    } else {
        node.str("ports", link.q("mport"));
    }
    node.str("sni", link.q_any(&["sni", "peer"]));
    let obfs = link.q("obfs");
    if obfs != "none" {
        node.str("obfs", obfs);
        node.str("obfs-password", link.q("obfs-password"));
    }
    if parse_bool(link.q("insecure")) {
        node.flag("skip-cert-verify", true);
    }
    node.str("fingerprint", link.q("pinSHA256"));
    node.list("alpn", link.q("alpn"));
    node.str("up", link.q("up"));
    node.str("down", link.q("down"));
    Ok(node.0)
}

fn parse_tuic(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(443)?;
    let mut node = Node::new(&link.name_or("TUIC", port), "tuic", &link.host, port);
    match link.user.split_once(':') {
        Some((uuid, password)) => {
            node.str("uuid", &url_decode(uuid));
            node.str("password", &url_decode(password));
        }
        // TUIC v4 links carry a token instead of uuid:password
        None if !link.user.is_empty() => node.str("token", &url_decode(&link.user)),
        None => bail!("missing uuid:password"),
    }
    node.flag("udp", true);
    node.str(
        "congestion-controller",
        link.q_any(&["congestion_control", "congestion-controller", "congestion"]),
    );
    node.str("udp-relay-mode", link.q_any(&["udp_relay_mode", "udp-relay-mode"]));
    node.list("alpn", link.q("alpn"));
    node.str("sni", link.q("sni"));
    if parse_bool(link.q_any(&["disable_sni", "disable-sni"])) {
        node.flag("disable-sni", true);
    }
    if parse_bool(link.q_any(&["allow_insecure", "allowInsecure", "insecure", "skip-cert-verify"])) {
        node.flag("skip-cert-verify", true);
    }
    Ok(node.0)
}

fn parse_anytls(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(443)?;
    let mut node = Node::new(&link.name_or("AnyTLS", port), "anytls", &link.host, port);
    let (user, password) = match link.user.split_once(':') {
        Some((u, p)) => (url_decode(u), url_decode(p)),
        None => (url_decode(&link.user), url_decode(&link.user)),
    };
    if password.is_empty() {
        bail!("missing password");
    }
    node.str("username", &user);
    node.str("password", &password);
    node.str("sni", link.q("sni"));
    node.str("fingerprint", link.q("hpkp"));
    node.str("client-fingerprint", link.q("fp"));
    if parse_bool(link.q("insecure")) {
        node.flag("skip-cert-verify", true);
    }
    node.flag("udp", true);
    Ok(node.0)
}

fn parse_socks(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = parse_port(link.port.as_deref().unwrap_or_default())?;
    let mut node = Node::new(&link.name_or("SOCKS5", port), "socks5", &link.host, port);
    if !link.user.is_empty() {
        // user info is either `user:pass` or Base64(`user:pass`)
        let raw = url_decode(&link.user);
        let info = if raw.contains(':') {
            raw
        } else {
            b64_decode_or_raw(&raw)
        };
        let (user, pass) = info.split_once(':').unwrap_or((info.as_str(), ""));
        node.str("username", user);
        node.str("password", pass);
    }
    node.flag("udp", true);
    Ok(node.0)
}

/// `wireguard://privatekey@host:port?publickey=..&address=..&mtu=..&reserved=..`
fn parse_wireguard(line: &str) -> Result<Mapping> {
    let link = Link::parse(line)?;
    let port = link.port_or(51820)?;
    let mut node = Node::new(&link.name_or("WireGuard", port), "wireguard", &link.host, port);
    let private_key = url_decode(&link.user);
    let public_key = link.q_any(&["publickey", "public-key", "peer-public-key"]);
    if private_key.is_empty() || public_key.is_empty() {
        bail!("wireguard link needs a private key and a publickey");
    }
    node.str("private-key", &private_key);
    node.str("public-key", public_key);
    node.str("pre-shared-key", link.q_any(&["presharedkey", "pre-shared-key"]));
    for addr in link.q_any(&["address", "ip"]).split(',').map(str::trim) {
        let ip = addr.split('/').next().unwrap_or_default();
        if ip.contains(':') {
            node.str("ipv6", ip);
        } else {
            node.str("ip", ip);
        }
    }
    if let Ok(mtu) = link.q("mtu").parse::<u16>() {
        node.set("mtu", Value::Number(mtu.into()));
    }
    let reserved: Vec<Value> = link
        .q("reserved")
        .split(',')
        .filter_map(|n| n.trim().parse::<u8>().ok())
        .map(|n| Value::Number(n.into()))
        .collect();
    if reserved.len() == 3 {
        node.set("reserved", Value::Sequence(reserved));
    }
    node.flag("udp", true);
    Ok(node.0)
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// Ensure every proxy has a unique, non-empty `name`.
fn dedupe_proxy_names(proxies: &mut [Mapping]) {
    let mut used: HashSet<String> = HashSet::new();
    for proxy in proxies.iter_mut() {
        let original = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or("Node")
            .to_owned();
        let mut candidate = original.clone();
        let mut n = 2;
        while !used.insert(candidate.clone()) {
            candidate = format!("{original} #{n}");
            n += 1;
        }
        proxy.insert(s("name"), Value::String(candidate));
    }
}

/// Rename duplicate proxies in place and return, per original name, the names
/// assigned to its successive occurrences.
fn rename_duplicate_proxies(proxies: &mut [Value]) -> HashMap<String, Vec<String>> {
    let mut occurrences: HashMap<String, Vec<String>> = HashMap::new();
    for proxy in proxies.iter_mut() {
        let Some(m) = proxy.as_mapping_mut() else { continue };
        let Some(name) = m.get("name").and_then(|v| v.as_str()).map(str::to_owned) else {
            continue;
        };
        let assigned = occurrences.entry(name.clone()).or_default();
        let new_name = if assigned.is_empty() {
            name
        } else {
            let renamed = format!("{name} #{}", assigned.len() + 1);
            m.insert(s("name"), s(&renamed));
            renamed
        };
        assigned.push(new_name);
    }
    occurrences
}

fn rewrite_group_refs(list: &mut [Value], occurrences: &HashMap<String, Vec<String>>) {
    let mut cursor: HashMap<String, usize> = HashMap::new();
    for entry in list.iter_mut() {
        let Some(ref_name) = entry.as_str().map(str::to_owned) else {
            continue;
        };
        let Some(assigned) = occurrences.get(&ref_name).filter(|a| a.len() > 1) else {
            continue;
        };
        let idx = cursor.entry(ref_name).or_insert(0);
        if let Some(new_name) = assigned.get(*idx) {
            *entry = s(new_name);
            *idx += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

fn non_empty_seq(v: Option<&Value>) -> bool {
    v.and_then(|v| v.as_sequence()).is_some_and(|s| !s.is_empty())
}

fn first_group_name(root: &Mapping) -> Option<String> {
    root.get("proxy-groups")?
        .as_sequence()?
        .iter()
        .find_map(|g| g.get("name").and_then(|n| n.as_str()).map(str::to_owned))
}

/// An auto-select group plus a manual one. DIRECT is offered in the manual
/// group so traffic can be sent outside the tunnel without a separate group.
fn default_groups(proxy_names: Vec<Value>, providers: &[Value]) -> Vec<Value> {
    let mut auto = mapping(&[
        ("name", s(AUTO_GROUP)),
        ("type", s("url-test")),
        ("url", s("http://www.gstatic.com/generate_204")),
        ("interval", Value::Number(300u64.into())),
        ("tolerance", Value::Number(50u64.into())),
    ]);
    let mut manual = mapping(&[("name", s(MANUAL_GROUP)), ("type", s("select"))]);

    let mut manual_list = vec![s(AUTO_GROUP)];
    manual_list.extend(proxy_names.iter().cloned());
    manual_list.push(s("DIRECT"));
    if proxy_names.is_empty() {
        // provider-only config: url-test needs at least one member, which
        // `use` provides; DIRECT keeps it valid if a provider is empty.
        auto.insert(s("proxies"), Value::Sequence(vec![s("DIRECT")]));
    } else {
        auto.insert(s("proxies"), Value::Sequence(proxy_names));
    }
    manual.insert(s("proxies"), Value::Sequence(manual_list));
    if !providers.is_empty() {
        auto.insert(s("use"), Value::Sequence(providers.to_vec()));
        manual.insert(s("use"), Value::Sequence(providers.to_vec()));
    }
    vec![Value::Mapping(auto), Value::Mapping(manual)]
}

/// Loopback/LAN/private traffic must stay DIRECT or local network access
/// (printers, routers, NAS, localhost dev servers) breaks once the tunnel is
/// up. Everything else falls through to `target`. Users layer their own
/// site/app rules on top via the Rules enhancement (`prepend`).
fn default_rules(target: &str) -> Value {
    let mut rules: Vec<Value> = [
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    ]
    .iter()
    .map(|r| s(r))
    .collect();
    rules.push(Value::String(format!("MATCH,{target}")));
    Value::Sequence(rules)
}

fn build_clash_yaml(proxies: Vec<Mapping>) -> Result<String> {
    let proxy_names: Vec<Value> = proxies.iter().filter_map(|p| p.get("name").cloned()).collect();

    let mut root = Mapping::new();
    root.insert(
        s("proxies"),
        Value::Sequence(proxies.into_iter().map(Value::Mapping).collect()),
    );
    root.insert(s("proxy-groups"), Value::Sequence(default_groups(proxy_names, &[])));
    root.insert(s("rules"), default_rules(MANUAL_GROUP));
    // Required for PROCESS-NAME / PROCESS-PATH rules (per-application routing)
    // to match. mihomo's default (`strict`) skips process lookup in cases where
    // app rules would otherwise silently never fire.
    root.insert(s("find-process-mode"), s("always"));

    serde_yaml_ng::to_string(&Value::Mapping(root)).context("failed to serialize Clash YAML")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "proxy_parser_tests.rs"]
mod tests;
