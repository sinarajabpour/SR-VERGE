use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde_yaml_ng::{Mapping, Value};
use std::collections::HashMap;

/// Known proxy URI schemes we can parse.
const KNOWN_SCHEMES: &[&str] = &[
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria2://",
    "hy2://",
    "tuic://",
];

/// Attempt to detect and convert a Base64-encoded (or plain) proxy URI list
/// into a valid Clash Meta YAML string.
///
/// Returns `Ok(None)` when the content does not look like a URI list at all,
/// so the caller can fall through to normal YAML handling without error.
pub fn try_convert_txt_to_yaml(raw: &str) -> Result<Option<String>> {
    let text = decode_if_base64(raw.trim());

    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let uri_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| KNOWN_SCHEMES.iter().any(|s| l.to_ascii_lowercase().starts_with(s)))
        .collect();

    if uri_lines.is_empty() {
        return Ok(None);
    }

    let mut proxies: Vec<Mapping> = Vec::new();
    for line in &uri_lines {
        match parse_proxy_uri(line) {
            Ok(node) => proxies.push(node),
            Err(e) => log::warn!("[proxy_parser] skipping unparseable URI: {e}"),
        }
    }

    if proxies.is_empty() {
        bail!(
            "subscription contained {} URI lines but none could be parsed",
            uri_lines.len()
        );
    }

    // mihomo requires unique proxy names; rename duplicates by appending a counter.
    dedupe_proxy_names(&mut proxies);

    let yaml = build_clash_yaml(proxies)?;
    Ok(Some(yaml))
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
    let map = match root.as_mapping_mut() {
        Some(m) => m,
        None => return Ok(None),
    };

    // For each original name, the ordered list of names assigned to its
    // successive occurrences (index 0 == the unchanged first occurrence).
    let mut occurrences: HashMap<String, Vec<String>> = HashMap::new();
    let mut any_dupe = false;

    {
        let proxies = match map.get_mut("proxies").and_then(|v| v.as_sequence_mut()) {
            Some(seq) => seq,
            None => return Ok(None),
        };

        let mut counts: HashMap<String, usize> = HashMap::new();
        for proxy in proxies.iter_mut() {
            let m = match proxy.as_mapping_mut() {
                Some(m) => m,
                None => continue,
            };
            let name = match m.get("name").and_then(|v| v.as_str()) {
                Some(s) => s.to_owned(),
                None => continue,
            };
            let count = counts.entry(name.clone()).or_insert(0);
            *count += 1;
            let assigned = if *count == 1 {
                name.clone()
            } else {
                any_dupe = true;
                let renamed = format!("{name} #{}", *count);
                m.insert(Value::String("name".to_owned()), Value::String(renamed.clone()));
                renamed
            };
            occurrences.entry(name).or_default().push(assigned);
        }
    }

    if !any_dupe {
        return Ok(None);
    }

    // Rewrite proxy-group references positionally.
    if let Some(groups) = map.get_mut("proxy-groups").and_then(|v| v.as_sequence_mut()) {
        for group in groups.iter_mut() {
            let gm = match group.as_mapping_mut() {
                Some(m) => m,
                None => continue,
            };
            let glist = match gm.get_mut("proxies").and_then(|v| v.as_sequence_mut()) {
                Some(l) => l,
                None => continue,
            };
            let mut cursor: HashMap<String, usize> = HashMap::new();
            for entry in glist.iter_mut() {
                let ref_name = match entry.as_str() {
                    Some(s) => s.to_owned(),
                    None => continue,
                };
                if let Some(assigned_list) = occurrences.get(&ref_name)
                    && assigned_list.len() > 1
                {
                    let idx = cursor.entry(ref_name).or_insert(0);
                    if let Some(new_name) = assigned_list.get(*idx) {
                        *entry = Value::String(new_name.clone());
                        *idx += 1;
                    }
                }
            }
        }
    }

    let out = serde_yaml_ng::to_string(&root).context("failed to serialize deduped config")?;
    Ok(Some(out))
}

/// Apply SR Verge's import transforms to raw remote subscription text:
///
/// 1. If the body is a Base64-encoded proxy-URI list (a `.txt` subscription),
///    convert it to Clash Meta YAML.
/// 2. Deduplicate proxy names so mihomo (which rejects duplicates) accepts it.
///
/// Any step that does not apply or fails is logged and skipped, so the returned
/// string is always safe to feed to the normal YAML validation path.
pub fn normalize_subscription(data: &str) -> String {
    let converted = match try_convert_txt_to_yaml(data) {
        Ok(Some(yaml)) => {
            log::info!("[profile] converted txt subscription to Clash YAML");
            yaml
        }
        Ok(None) => data.to_owned(),
        Err(e) => {
            log::warn!("[profile] txt conversion attempted but failed: {e}");
            data.to_owned()
        }
    };

    match dedupe_clash_yaml(&converted) {
        Ok(Some(yaml)) => {
            log::info!("[profile] deduplicated proxy names in config");
            yaml
        }
        Ok(None) => converted,
        Err(e) => {
            log::warn!("[profile] proxy name dedup failed: {e}");
            converted
        }
    }
}

// ---------------------------------------------------------------------------
// Base64 detection
// ---------------------------------------------------------------------------

fn decode_if_base64(s: &str) -> String {
    // Remove whitespace that some encoders add
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        // Sanity-check: decoded text should contain at least one known scheme
        if let Ok(bytes) = engine.decode(&stripped)
            && let Ok(decoded) = String::from_utf8(bytes)
            && KNOWN_SCHEMES.iter().any(|s| decoded.to_ascii_lowercase().contains(s))
        {
            return decoded;
        }
    }
    s.to_owned()
}

// ---------------------------------------------------------------------------
// Dispatch by scheme
// ---------------------------------------------------------------------------

fn parse_proxy_uri(line: &str) -> Result<Mapping> {
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("vmess://") {
        parse_vmess(line)
    } else if lower.starts_with("vless://") {
        parse_vless(line)
    } else if lower.starts_with("trojan://") {
        parse_trojan(line)
    } else if lower.starts_with("ssr://") {
        parse_ssr(line)
    } else if lower.starts_with("ss://") {
        parse_ss(line)
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria2(line)
    } else if lower.starts_with("tuic://") {
        parse_tuic(line)
    } else {
        bail!("unsupported scheme: {line}")
    }
}

// ---------------------------------------------------------------------------
// URI helpers
// ---------------------------------------------------------------------------

fn strip_scheme<'a>(uri: &'a str, scheme: &str) -> &'a str {
    &uri[scheme.len()..]
}

fn url_decode(s: &str) -> String {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_owned())
}

/// Parse `user:pass@host:port?query#fragment` (auth part may be absent).
struct ParsedUrl {
    auth: String,
    host: String,
    port: Option<String>,
    query: HashMap<String, String>,
    fragment: Option<String>,
}

fn parse_url_like(input: &str) -> Result<ParsedUrl> {
    // Split fragment
    let (without_frag, fragment) = match input.split_once('#') {
        Some((a, b)) => (a, Some(url_decode(b))),
        None => (input, None),
    };

    // Split query
    let (without_query, query_str) = match without_frag.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (without_frag, None),
    };

    let query = parse_query_string(query_str.unwrap_or(""));

    // auth@host:port
    let (auth, host_port) = match without_query.split_once('@') {
        Some((a, b)) => (url_decode(a), b),
        None => (String::new(), without_query),
    };

    // Handle IPv6 [::1]:port
    let (host, port) = if host_port.starts_with('[') {
        match host_port.find(']') {
            Some(idx) => {
                let host = host_port[1..idx].to_owned();
                let after = &host_port[idx + 1..];
                let port = after.strip_prefix(':').map(|p| p.to_owned());
                (host, port)
            }
            None => bail!("invalid IPv6 address: {host_port}"),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p.to_owned())),
            None => (host_port.to_owned(), None),
        }
    };

    Ok(ParsedUrl {
        auth,
        host,
        port,
        query,
        fragment,
    })
}

fn parse_query_string(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, url_decode(v)),
            None => (pair, String::new()),
        };
        if !k.is_empty() {
            map.insert(k.to_owned(), v);
        }
    }
    map
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>().with_context(|| format!("invalid port: {s}"))
}

fn b64_decode_str(s: &str) -> String {
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(&stripped)
            && let Ok(text) = String::from_utf8(bytes)
        {
            return text;
        }
    }
    s.to_owned()
}

fn insert_str(m: &mut Mapping, k: &str, v: impl Into<String>) {
    let s: String = v.into();
    if !s.is_empty() {
        m.insert(Value::String(k.to_owned()), Value::String(s));
    }
}

fn insert_val(m: &mut Mapping, k: &str, v: Value) {
    m.insert(Value::String(k.to_owned()), v);
}

// ---------------------------------------------------------------------------
// VMess parser
// ---------------------------------------------------------------------------

fn parse_vmess(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "vmess://");
    let content = b64_decode_str(after);

    // V2rayN JSON format
    let params: serde_json::Value =
        serde_json::from_str(&content).with_context(|| format!("vmess JSON parse failed: {content}"))?;

    let server = params["add"].as_str().unwrap_or("").to_owned();
    let port_val = params["port"]
        .as_u64()
        .map(|n| n.to_string())
        .or_else(|| params["port"].as_str().map(|s| s.to_owned()))
        .unwrap_or_default();
    let port = parse_port(&port_val)?;

    let name = params["ps"]
        .as_str()
        .or_else(|| params["remarks"].as_str())
        .unwrap_or(&format!("VMess {server}:{port}"))
        .trim()
        .to_owned();

    let uuid = params["id"].as_str().unwrap_or("").to_owned();
    let alter_id: u64 = params["aid"]
        .as_u64()
        .or_else(|| params["aid"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0);

    let cipher = params["scy"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("auto")
        .to_owned();

    let tls_raw = params["tls"].as_str().unwrap_or("");
    let tls = tls_raw == "tls" || tls_raw == "true" || tls_raw == "1";

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "vmess");
    insert_str(&mut m, "server", &server);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "uuid", &uuid);
    insert_val(&mut m, "alterId", Value::Number(alter_id.into()));
    insert_str(&mut m, "cipher", &cipher);
    insert_val(&mut m, "tls", Value::Bool(tls));

    if tls && let Some(sni) = params["sni"].as_str().filter(|s| !s.is_empty()) {
        insert_str(&mut m, "servername", sni);
    }

    let net = params["net"].as_str().unwrap_or("tcp");
    let host = params["host"].as_str().unwrap_or("");
    let path = params["path"].as_str().unwrap_or("/");

    match net {
        "ws" => {
            insert_str(&mut m, "network", "ws");
            let mut ws_opts = Mapping::new();
            if !path.is_empty() {
                insert_str(&mut ws_opts, "path", path);
            }
            if !host.is_empty() {
                let mut headers = Mapping::new();
                insert_str(&mut headers, "Host", host);
                insert_val(&mut ws_opts, "headers", Value::Mapping(headers));
            }
            if !ws_opts.is_empty() {
                insert_val(&mut m, "ws-opts", Value::Mapping(ws_opts));
            }
        }
        "grpc" => {
            insert_str(&mut m, "network", "grpc");
            let svc = params["path"].as_str().filter(|s| !s.is_empty()).unwrap_or("");
            if !svc.is_empty() {
                let mut grpc_opts = Mapping::new();
                insert_str(&mut grpc_opts, "grpc-service-name", svc);
                insert_val(&mut m, "grpc-opts", Value::Mapping(grpc_opts));
            }
        }
        "h2" => {
            insert_str(&mut m, "network", "h2");
            let mut h2_opts = Mapping::new();
            if !host.is_empty() {
                insert_str(&mut h2_opts, "host", host);
            }
            if !path.is_empty() {
                insert_str(&mut h2_opts, "path", path);
            }
            if !h2_opts.is_empty() {
                insert_val(&mut m, "h2-opts", Value::Mapping(h2_opts));
            }
        }
        _ => {}
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// VLESS parser
// ---------------------------------------------------------------------------

fn parse_vless(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "vless://");
    let parsed = parse_url_like(after)?;

    let port = parse_port(parsed.port.as_deref().unwrap_or("443"))?;
    let name = parsed
        .fragment
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("VLESS {}:{}", parsed.host, port));

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "vless");
    insert_str(&mut m, "server", &parsed.host);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "uuid", &parsed.auth);

    let q = &parsed.query;

    let security = q.get("security").map(|s| s.as_str()).unwrap_or("");
    let tls = !security.is_empty() && security != "none";
    if tls {
        insert_val(&mut m, "tls", Value::Bool(true));
    }

    if let Some(sni) = q.get("sni").or_else(|| q.get("peer")) {
        insert_str(&mut m, "servername", sni);
    }
    if let Some(flow) = q.get("flow").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "flow", flow);
    }
    if let Some(fp) = q.get("fp").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "client-fingerprint", fp);
    }
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        let alpn_list: Vec<Value> = alpn.split(',').map(|s| Value::String(s.to_owned())).collect();
        insert_val(&mut m, "alpn", Value::Sequence(alpn_list));
    }

    // Reality opts
    if security == "reality" {
        let mut reality_opts = Mapping::new();
        if let Some(pbk) = q.get("pbk").filter(|s| !s.is_empty()) {
            insert_str(&mut reality_opts, "public-key", pbk);
        }
        if let Some(sid) = q.get("sid").filter(|s| !s.is_empty()) {
            insert_str(&mut reality_opts, "short-id", sid);
        }
        if !reality_opts.is_empty() {
            insert_val(&mut m, "reality-opts", Value::Mapping(reality_opts));
        }
    }

    // Transport
    let net_type = q.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let host = q.get("host").map(|s| s.as_str()).unwrap_or("");
    let path = q.get("path").map(|s| s.as_str()).unwrap_or("");

    match net_type {
        "ws" | "websocket" => {
            insert_str(&mut m, "network", "ws");
            let mut ws_opts = Mapping::new();
            if !path.is_empty() {
                insert_str(&mut ws_opts, "path", path);
            }
            if !host.is_empty() {
                let mut headers = Mapping::new();
                insert_str(&mut headers, "Host", host);
                insert_val(&mut ws_opts, "headers", Value::Mapping(headers));
            }
            if !ws_opts.is_empty() {
                insert_val(&mut m, "ws-opts", Value::Mapping(ws_opts));
            }
        }
        "grpc" => {
            insert_str(&mut m, "network", "grpc");
            if !path.is_empty() {
                let mut grpc_opts = Mapping::new();
                insert_str(&mut grpc_opts, "grpc-service-name", path);
                insert_val(&mut m, "grpc-opts", Value::Mapping(grpc_opts));
            }
        }
        "h2" => {
            insert_str(&mut m, "network", "h2");
            let mut h2_opts = Mapping::new();
            if !host.is_empty() {
                insert_str(&mut h2_opts, "host", host);
            }
            if !path.is_empty() {
                insert_str(&mut h2_opts, "path", path);
            }
            if !h2_opts.is_empty() {
                insert_val(&mut m, "h2-opts", Value::Mapping(h2_opts));
            }
        }
        _ => {}
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Trojan parser
// ---------------------------------------------------------------------------

fn parse_trojan(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "trojan://");
    let parsed = parse_url_like(after)?;

    let port = parse_port(parsed.port.as_deref().unwrap_or("443"))?;
    let password = url_decode(&parsed.auth);
    let name = parsed
        .fragment
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("Trojan {}:{}", parsed.host, port));

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "trojan");
    insert_str(&mut m, "server", &parsed.host);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "password", &password);

    let q = &parsed.query;
    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "sni", sni);
    }
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        let alpn_list: Vec<Value> = alpn.split(',').map(|s| Value::String(s.to_owned())).collect();
        insert_val(&mut m, "alpn", Value::Sequence(alpn_list));
    }
    if let Some(fp) = q.get("fp").or_else(|| q.get("fingerprint")).filter(|s| !s.is_empty()) {
        insert_str(&mut m, "fingerprint", fp);
    }

    let net_type = q.get("type").map(|s| s.as_str()).unwrap_or("");
    let host = q.get("host").map(|s| s.as_str()).unwrap_or("");
    let path = q.get("path").map(|s| s.as_str()).unwrap_or("");

    if net_type == "ws" {
        insert_str(&mut m, "network", "ws");
        let mut ws_opts = Mapping::new();
        if !host.is_empty() {
            let mut headers = Mapping::new();
            insert_str(&mut headers, "Host", host);
            insert_val(&mut ws_opts, "headers", Value::Mapping(headers));
        }
        if !path.is_empty() {
            insert_str(&mut ws_opts, "path", path);
        }
        if !ws_opts.is_empty() {
            insert_val(&mut m, "ws-opts", Value::Mapping(ws_opts));
        }
    } else if net_type == "grpc" {
        insert_str(&mut m, "network", "grpc");
        if !path.is_empty() {
            let mut grpc_opts = Mapping::new();
            insert_str(&mut grpc_opts, "grpc-service-name", path);
            insert_val(&mut m, "grpc-opts", Value::Mapping(grpc_opts));
        }
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Shadowsocks parser
// ---------------------------------------------------------------------------

fn parse_ss(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "ss://");

    // Split off fragment (name)
    let (without_frag, frag) = match after.split_once('#') {
        Some((a, b)) => (a, Some(url_decode(b))),
        None => (after, None),
    };

    // Split off query
    let (main_raw, query_raw) = match without_frag.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (without_frag, None),
    };

    // main part may be plain `userinfo@host:port` or base64(`method:pass`)@host:port
    let main = if main_raw.contains('@') {
        main_raw.to_owned()
    } else {
        b64_decode_str(main_raw)
    };

    let at_idx = main.rfind('@').context("ss uri missing '@'")?;
    let user_info_raw = b64_decode_str(&main[..at_idx]);
    let server_part = main[at_idx + 1..].split('/').next().unwrap_or("");

    let port_idx = server_part.rfind(':').context("ss uri missing port")?;
    let server = server_part[..port_idx].to_owned();
    let port = parse_port(&server_part[port_idx + 1..])?;

    let (cipher, password) = match user_info_raw.split_once(':') {
        Some((c, p)) => (c.to_owned(), p.to_owned()),
        None => bail!("ss uri invalid user info"),
    };

    let name = frag
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("SS {server}:{port}"));

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "ss");
    insert_str(&mut m, "server", &server);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "cipher", &cipher);
    insert_str(&mut m, "password", &password);

    if let Some(qs) = query_raw {
        let params = parse_query_string(qs);
        if let Some(plugin_raw) = params.get("plugin") {
            let parts: Vec<&str> = plugin_raw.splitn(2, ';').collect();
            let plugin_name = parts[0];
            match plugin_name {
                "obfs-local" | "simple-obfs" => {
                    insert_str(&mut m, "plugin", "obfs");
                    let opts_raw = parts.get(1).copied().unwrap_or("");
                    let opts = parse_query_string(opts_raw);
                    let mut plugin_opts = Mapping::new();
                    if let Some(mode) = opts.get("obfs") {
                        insert_str(&mut plugin_opts, "mode", mode);
                    }
                    if let Some(host) = opts.get("obfs-host") {
                        insert_str(&mut plugin_opts, "host", host);
                    }
                    insert_val(&mut m, "plugin-opts", Value::Mapping(plugin_opts));
                }
                "v2ray-plugin" => {
                    insert_str(&mut m, "plugin", "v2ray-plugin");
                    let opts_raw = parts.get(1).copied().unwrap_or("");
                    let opts = parse_query_string(opts_raw);
                    let mut plugin_opts = Mapping::new();
                    insert_str(&mut plugin_opts, "mode", "websocket");
                    if let Some(host) = opts.get("obfs-host").or_else(|| opts.get("host")) {
                        insert_str(&mut plugin_opts, "host", host);
                    }
                    if let Some(path) = opts.get("path") {
                        insert_str(&mut plugin_opts, "path", path);
                    }
                    insert_val(&mut m, "plugin-opts", Value::Mapping(plugin_opts));
                }
                _ => {}
            }
        }
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// ShadowsocksR parser
// ---------------------------------------------------------------------------

fn parse_ssr(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "ssr://");
    let line = b64_decode_str(after);

    // Find the protocol field boundary (e.g. ":origin", ":auth_sha1_v4", ":auth_aes128_md5")
    let split_idx = line
        .find(":origin")
        .or_else(|| line.find(":auth_"))
        .or_else(|| line.find(":plain"))
        .context("SSR uri: cannot find protocol boundary")?;

    let server_port_str = &line[..split_idx];
    let port_idx = server_port_str.rfind(':').context("SSR uri missing port")?;
    let server = server_port_str[..port_idx].to_owned();
    let port = parse_port(&server_port_str[port_idx + 1..])?;

    // Remaining: protocol:cipher:obfs:base64pass/?params
    let rest = &line[split_idx + 1..];
    let (main_part, addon_part) = match rest.split_once("/?") {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };

    let parts: Vec<&str> = main_part.splitn(4, ':').collect();
    if parts.len() < 4 {
        bail!("SSR uri: malformed params");
    }
    let protocol = parts[0].to_owned();
    let cipher = parts[1].to_owned();
    let obfs = parts[2].to_owned();
    let password = b64_decode_str(parts[3]);

    let addons = addon_part.map(parse_query_string).unwrap_or_default();
    let name = addons
        .get("remarks")
        .map(|r| b64_decode_str(r).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| server.clone());

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "ssr");
    insert_str(&mut m, "server", &server);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "cipher", &cipher);
    insert_str(&mut m, "password", &password);
    insert_str(&mut m, "protocol", &protocol);
    insert_str(&mut m, "obfs", &obfs);

    if let Some(pp) = addons.get("protoparam").filter(|s| !s.is_empty()) {
        insert_str(
            &mut m,
            "protocol-param",
            b64_decode_str(pp).replace(char::is_whitespace, ""),
        );
    }
    if let Some(op) = addons.get("obfsparam").filter(|s| !s.is_empty()) {
        insert_str(
            &mut m,
            "obfs-param",
            b64_decode_str(op).replace(char::is_whitespace, ""),
        );
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Hysteria2 parser
// ---------------------------------------------------------------------------

fn parse_hysteria2(uri: &str) -> Result<Mapping> {
    let after = if uri.to_ascii_lowercase().starts_with("hy2://") {
        strip_scheme(uri, "hy2://")
    } else {
        strip_scheme(uri, "hysteria2://")
    };

    let parsed = parse_url_like(after)?;
    let port = parse_port(parsed.port.as_deref().unwrap_or("443"))?;
    let password = url_decode(&parsed.auth);
    let name = parsed
        .fragment
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("Hysteria2 {}:{}", parsed.host, port));

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "hysteria2");
    insert_str(&mut m, "server", &parsed.host);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "password", &password);

    let q = &parsed.query;
    if let Some(sni) = q.get("sni").or_else(|| q.get("peer")).filter(|s| !s.is_empty()) {
        insert_str(&mut m, "sni", sni);
    }
    if let Some(obfs) = q.get("obfs").filter(|s| !s.is_empty() && *s != "none") {
        insert_str(&mut m, "obfs", obfs);
    }
    if let Some(op) = q.get("obfs-password").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "obfs-password", op);
    }
    if let Some(insecure) = q.get("insecure") {
        insert_val(&mut m, "skip-cert-verify", Value::Bool(parse_bool(insecure)));
    }
    if let Some(pin) = q.get("pinSHA256").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "fingerprint", pin);
    }
    if let Some(mport) = q.get("mport").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "ports", mport);
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// TUIC parser
// ---------------------------------------------------------------------------

fn parse_tuic(uri: &str) -> Result<Mapping> {
    let after = strip_scheme(uri, "tuic://");
    let parsed = parse_url_like(after)?;

    let port = parse_port(parsed.port.as_deref().unwrap_or("443"))?;
    let name = parsed
        .fragment
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("TUIC {}:{}", parsed.host, port));

    // auth is uuid:password
    let (uuid, password_raw) = match parsed.auth.split_once(':') {
        Some((u, p)) => (u.to_owned(), p.to_owned()),
        None => bail!("TUIC uri: missing password in auth"),
    };
    let password = url_decode(&password_raw);

    let mut m = Mapping::new();
    insert_str(&mut m, "name", &name);
    insert_str(&mut m, "type", "tuic");
    insert_str(&mut m, "server", &parsed.host);
    insert_val(&mut m, "port", Value::Number(port.into()));
    insert_str(&mut m, "uuid", &uuid);
    insert_str(&mut m, "password", &password);

    let q = &parsed.query;
    if let Some(cc) = q.get("congestion-controller").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "congestion-controller", cc);
    }
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        let alpn_list: Vec<Value> = alpn.split(',').map(|s| Value::String(s.to_owned())).collect();
        insert_val(&mut m, "alpn", Value::Sequence(alpn_list));
    }
    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "sni", sni);
    }
    if let Some(udp) = q.get("udp-relay-mode").filter(|s| !s.is_empty()) {
        insert_str(&mut m, "udp-relay-mode", udp);
    }
    if let Some(insecure) = q.get("allow-insecure").or_else(|| q.get("skip-cert-verify")) {
        insert_val(&mut m, "skip-cert-verify", Value::Bool(parse_bool(insecure)));
    }
    if let Some(dsni) = q.get("disable-sni") {
        insert_val(&mut m, "disable-sni", Value::Bool(parse_bool(dsni)));
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// Ensure every proxy has a unique `name`. mihomo rejects configs with
/// duplicate proxy names, which is common in real-world subscriptions.
fn dedupe_proxy_names(proxies: &mut [Mapping]) {
    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    for proxy in proxies.iter_mut() {
        let original = proxy.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        if used.insert(original.clone()) {
            continue;
        }
        // Name taken — find the next free "name #N".
        let mut n = 2;
        let mut candidate = format!("{original} #{n}");
        while !used.insert(candidate.clone()) {
            n += 1;
            candidate = format!("{original} #{n}");
        }
        proxy.insert(Value::String("name".to_owned()), Value::String(candidate));
    }
}

// ---------------------------------------------------------------------------
// YAML builder
// ---------------------------------------------------------------------------

fn build_clash_yaml(proxies: Vec<Mapping>) -> Result<String> {
    let proxy_names: Vec<Value> = proxies.iter().filter_map(|p| p.get("name").cloned()).collect();

    let proxies_val: Value = Value::Sequence(proxies.into_iter().map(Value::Mapping).collect());

    // Minimal url-test group
    let mut group = Mapping::new();
    insert_str(&mut group, "name", "Subscription");
    insert_str(&mut group, "type", "url-test");
    insert_val(&mut group, "proxies", Value::Sequence(proxy_names.clone()));
    insert_str(&mut group, "url", "http://www.gstatic.com/generate_204");
    insert_val(&mut group, "interval", Value::Number(300u64.into()));

    // Also a manual select group
    let mut select_group = Mapping::new();
    insert_str(&mut select_group, "name", "Manual");
    insert_str(&mut select_group, "type", "select");
    let mut manual_proxies = vec![Value::String("Subscription".to_owned())];
    manual_proxies.extend(proxy_names);
    insert_val(&mut select_group, "proxies", Value::Sequence(manual_proxies));

    let groups_val = Value::Sequence(vec![Value::Mapping(group), Value::Mapping(select_group)]);

    // Minimal rules
    let rules_val = Value::Sequence(vec![Value::String("MATCH,Manual".to_owned())]);

    let mut root = Mapping::new();
    root.insert(Value::String("proxies".to_owned()), proxies_val);
    root.insert(Value::String("proxy-groups".to_owned()), groups_val);
    root.insert(Value::String("rules".to_owned()), rules_val);

    serde_yaml_ng::to_string(&Value::Mapping(root)).context("failed to serialize Clash YAML")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::bool_assert_comparison,
        clippy::needless_raw_string_hashes,
        clippy::useless_vec
    )]
    use super::*;

    #[test]
    fn test_vmess_v2rayn() {
        // {"add":"1.2.3.4","port":"443","id":"uuid-here","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com","ps":"Test VMess"}
        let payload = r#"{"add":"1.2.3.4","port":"443","id":"uuid-here","aid":"0","net":"ws","host":"example.com","path":"/ws","tls":"tls","sni":"example.com","ps":"Test VMess"}"#;
        let encoded = general_purpose::STANDARD.encode(payload);
        let uri = format!("vmess://{encoded}");
        let result = parse_vmess(&uri).unwrap();
        assert_eq!(result["name"].as_str().unwrap(), "Test VMess");
        assert_eq!(result["type"].as_str().unwrap(), "vmess");
        assert_eq!(result["server"].as_str().unwrap(), "1.2.3.4");
        assert_eq!(result["tls"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_vless_basic() {
        let uri =
            "vless://uuid-1234@1.2.3.4:443?security=tls&sni=example.com&type=ws&path=/ws&host=example.com#Test+VLESS";
        let result = parse_vless(uri).unwrap();
        assert_eq!(result["type"].as_str().unwrap(), "vless");
        assert_eq!(result["server"].as_str().unwrap(), "1.2.3.4");
        assert_eq!(result["uuid"].as_str().unwrap(), "uuid-1234");
        assert_eq!(result["tls"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_trojan_basic() {
        let uri = "trojan://password123@1.2.3.4:443?sni=example.com#Test+Trojan";
        let result = parse_trojan(uri).unwrap();
        assert_eq!(result["type"].as_str().unwrap(), "trojan");
        assert_eq!(result["password"].as_str().unwrap(), "password123");
        assert_eq!(result["sni"].as_str().unwrap(), "example.com");
    }

    #[test]
    fn test_ss_sip002() {
        // ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#Test+SS
        let user_info = general_purpose::STANDARD.encode("aes-128-gcm:password");
        let uri = format!("ss://{user_info}@1.2.3.4:8388#Test SS");
        let result = parse_ss(&uri).unwrap();
        assert_eq!(result["type"].as_str().unwrap(), "ss");
        assert_eq!(result["cipher"].as_str().unwrap(), "aes-128-gcm");
        assert_eq!(result["password"].as_str().unwrap(), "password");
    }

    #[test]
    fn test_hysteria2_basic() {
        let uri = "hysteria2://mypassword@1.2.3.4:443?sni=example.com&insecure=0#Test+HY2";
        let result = parse_hysteria2(uri).unwrap();
        assert_eq!(result["type"].as_str().unwrap(), "hysteria2");
        assert_eq!(result["password"].as_str().unwrap(), "mypassword");
        assert_eq!(result["sni"].as_str().unwrap(), "example.com");
    }

    #[test]
    fn test_tuic_basic() {
        let uri = "tuic://uuid-123:password@1.2.3.4:443?congestion-controller=bbr&sni=example.com#Test+TUIC";
        let result = parse_tuic(uri).unwrap();
        assert_eq!(result["type"].as_str().unwrap(), "tuic");
        assert_eq!(result["uuid"].as_str().unwrap(), "uuid-123");
        assert_eq!(result["password"].as_str().unwrap(), "password");
        assert_eq!(result["congestion-controller"].as_str().unwrap(), "bbr");
    }

    #[test]
    fn test_b64_subscription() {
        let uris = vec![
            "vless://uuid-abc@1.2.3.4:443?security=tls&sni=a.com#Node1",
            "trojan://pass@5.6.7.8:443?sni=b.com#Node2",
        ];
        let joined = uris.join("\n");
        let encoded = general_purpose::STANDARD.encode(&joined);
        let result = try_convert_txt_to_yaml(&encoded).unwrap().unwrap();
        assert!(result.contains("proxies:"));
        assert!(result.contains("Node1"));
        assert!(result.contains("Node2"));
    }

    #[test]
    fn test_duplicate_names_deduped() {
        let uris = vec![
            "trojan://pass@1.1.1.1:443?sni=a.com#DE",
            "trojan://pass@2.2.2.2:443?sni=b.com#DE",
            "trojan://pass@3.3.3.3:443?sni=c.com#DE",
        ];
        let joined = uris.join("\n");
        let encoded = general_purpose::STANDARD.encode(&joined);
        let result = try_convert_txt_to_yaml(&encoded).unwrap().unwrap();
        // All three names must be distinct in the output
        assert!(result.contains("name: DE\n") || result.contains("name: DE\r"));
        assert!(result.contains("DE #2"));
        assert!(result.contains("DE #3"));
    }

    #[test]
    fn test_dedupe_clash_yaml_with_groups() {
        let yaml = r#"
proxy-groups:
- name: Auto
  type: url-test
  proxies:
  - A
  - CZ
  - B
  - CZ
proxies:
- name: A
  type: ss
  server: 1.1.1.1
  port: 1
- name: CZ
  type: ss
  server: 2.2.2.2
  port: 2
- name: B
  type: ss
  server: 3.3.3.3
  port: 3
- name: CZ
  type: ss
  server: 4.4.4.4
  port: 4
"#;
        let out = dedupe_clash_yaml(yaml).unwrap().expect("should dedupe");
        // Second CZ proxy renamed
        assert!(out.contains("CZ #2"));
        // The group must reference both the original and renamed node
        let parsed: Value = serde_yaml_ng::from_str(&out).unwrap();
        let group_proxies = parsed["proxy-groups"][0]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(group_proxies, vec!["A", "CZ", "B", "CZ #2"]);
    }

    #[test]
    fn test_dedupe_clash_yaml_no_dupes_returns_none() {
        let yaml = "proxies:\n  - name: A\n    type: ss\n    server: 1.1.1.1\n    port: 1\n";
        assert!(dedupe_clash_yaml(yaml).unwrap().is_none());
    }

    #[test]
    fn test_plain_yaml_passthrough() {
        let yaml = "proxies:\n  - name: test\n    type: ss\n";
        let result = try_convert_txt_to_yaml(yaml).unwrap();
        assert!(result.is_none(), "plain YAML should not be converted");
    }
}
