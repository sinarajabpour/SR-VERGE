#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::bool_assert_comparison,
    clippy::needless_raw_string_hashes,
    clippy::useless_vec,
    clippy::panic
)]
use super::*;
use base64::engine::general_purpose;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn b64(s: &str) -> String {
    general_purpose::STANDARD.encode(s)
}

fn one(link: &str) -> Mapping {
    parse_proxy_uri(link).unwrap_or_else(|e| panic!("{link}: {e:#}"))
}

fn get<'a>(m: &'a Mapping, path: &str) -> &'a Value {
    let mut cur = m
        .get(path.split('.').next().unwrap())
        .unwrap_or_else(|| panic!("missing {path}"));
    for key in path.split('.').skip(1) {
        cur = cur.get(key).unwrap_or_else(|| panic!("missing {path}"));
    }
    cur
}

fn str_at<'a>(m: &'a Mapping, path: &str) -> &'a str {
    get(m, path)
        .as_str()
        .unwrap_or_else(|| panic!("{path} is not a string"))
}

fn convert(raw: &str) -> Value {
    let yaml = try_convert_txt_to_yaml(raw).unwrap().expect("should detect links");
    serde_yaml_ng::from_str(&yaml).unwrap()
}

fn proxy_names(cfg: &Value) -> Vec<String> {
    cfg["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// VMess
// ---------------------------------------------------------------------------

#[test]
fn vmess_v2rayn_ws_tls() {
    let json = r#"{"v":"2","ps":"🇩🇪 Germany","add":"104.16.1.1","port":"443","id":"UUID","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/vm?ed=2048","tls":"tls","sni":"","alpn":"h2,http/1.1","fp":"chrome"}"#
        .replace("UUID", UUID);
    let m = one(&format!("vmess://{}", b64(&json)));
    assert_eq!(str_at(&m, "name"), "🇩🇪 Germany");
    assert_eq!(str_at(&m, "type"), "vmess");
    assert_eq!(str_at(&m, "server"), "104.16.1.1");
    assert_eq!(get(&m, "port").as_u64(), Some(443));
    assert_eq!(str_at(&m, "uuid"), UUID);
    assert_eq!(get(&m, "tls").as_bool(), Some(true));
    // empty sni falls back to the ws Host, or TLS to the CDN IP fails
    assert_eq!(str_at(&m, "servername"), "cdn.example.com");
    assert_eq!(str_at(&m, "client-fingerprint"), "chrome");
    assert_eq!(str_at(&m, "network"), "ws");
    assert_eq!(str_at(&m, "ws-opts.path"), "/vm");
    assert_eq!(get(&m, "ws-opts.max-early-data").as_u64(), Some(2048));
    assert_eq!(str_at(&m, "ws-opts.headers.Host"), "cdn.example.com");
    assert_eq!(get(&m, "udp").as_bool(), Some(true));
    assert_eq!(get(&m, "alpn").as_sequence().unwrap().len(), 2);
}

#[test]
fn vmess_numeric_fields_and_grpc() {
    let json = format!(
        r#"{{"ps":"grpc","add":"a.example.com","port":2053,"id":"{UUID}","aid":0,"net":"grpc","path":"svc","tls":"tls","sni":"a.example.com"}}"#
    );
    let m = one(&format!("vmess://{}", b64(&json)));
    assert_eq!(get(&m, "port").as_u64(), Some(2053));
    assert_eq!(get(&m, "alterId").as_u64(), Some(0));
    assert_eq!(str_at(&m, "network"), "grpc");
    assert_eq!(str_at(&m, "grpc-opts.grpc-service-name"), "svc");
}

#[test]
fn vmess_tcp_http_header_and_no_tls() {
    let json = format!(
        r#"{{"ps":"http","add":"1.2.3.4","port":"80","id":"{UUID}","aid":"0","net":"tcp","type":"http","host":"bing.com","path":"/","tls":""}}"#
    );
    let m = one(&format!("vmess://{}", b64(&json)));
    assert_eq!(get(&m, "tls").as_bool(), Some(false));
    assert_eq!(str_at(&m, "network"), "http");
    assert_eq!(
        get(&m, "http-opts.headers.Host").as_sequence().unwrap()[0].as_str(),
        Some("bing.com")
    );
}

#[test]
fn vmess_url_safe_base64_without_padding() {
    let json = format!(r#"{{"ps":"x?","add":"1.2.3.4","port":"443","id":"{UUID}","net":"tcp"}}"#);
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(json);
    let m = one(&format!("vmess://{encoded}"));
    assert_eq!(str_at(&m, "name"), "x?");
}

#[test]
fn vmess_aead_share_link() {
    let m = one(&format!(
        "vmess://{UUID}@1.2.3.4:8443?type=ws&security=tls&path=%2Fws&host=h.example.com#AEAD"
    ));
    assert_eq!(str_at(&m, "name"), "AEAD");
    assert_eq!(str_at(&m, "cipher"), "auto");
    assert_eq!(str_at(&m, "ws-opts.path"), "/ws");
    assert_eq!(str_at(&m, "servername"), "h.example.com");
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

#[test]
fn vless_reality_vision() {
    let m = one(&format!(
        "vless://{UUID}@5.6.7.8:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.speedtest.net&fp=firefox&pbk=Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd&sid=6ba85179e30d4fc2&type=tcp&headerType=none#Reality%20NL"
    ));
    assert_eq!(str_at(&m, "name"), "Reality NL");
    assert_eq!(str_at(&m, "flow"), "xtls-rprx-vision");
    assert_eq!(get(&m, "tls").as_bool(), Some(true));
    assert_eq!(str_at(&m, "servername"), "www.speedtest.net");
    assert_eq!(str_at(&m, "client-fingerprint"), "firefox");
    assert_eq!(
        str_at(&m, "reality-opts.public-key"),
        "Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd"
    );
    assert_eq!(str_at(&m, "reality-opts.short-id"), "6ba85179e30d4fc2");
    assert!(m.get("encryption").is_none(), "encryption=none must not be passed on");
    assert!(m.get("network").is_none());
}

#[test]
fn vless_path_before_query_is_accepted() {
    // `host:port/?…` is what most panels (Marzban, 3x-ui, Hiddify) generate
    let m = one(&format!(
        "vless://{UUID}@cdn.example.com:443/?type=ws&encryption=none&host=cdn.example.com&path=%2F%3Fed%3D2560&security=tls&sni=cdn.example.com#WS"
    ));
    assert_eq!(get(&m, "port").as_u64(), Some(443));
    assert_eq!(str_at(&m, "ws-opts.path"), "/");
    assert_eq!(get(&m, "ws-opts.max-early-data").as_u64(), Some(2560));
    assert_eq!(str_at(&m, "ws-opts.early-data-header-name"), "Sec-WebSocket-Protocol");
}

#[test]
fn vless_grpc_uses_service_name() {
    let m = one(&format!(
        "vless://{UUID}@1.2.3.4:443?type=grpc&serviceName=mygrpc&security=tls&sni=a.com&mode=gun#gRPC"
    ));
    assert_eq!(str_at(&m, "network"), "grpc");
    assert_eq!(str_at(&m, "grpc-opts.grpc-service-name"), "mygrpc");
}

#[test]
fn vless_xhttp_httpupgrade_and_h2() {
    let x = one(&format!(
        "vless://{UUID}@1.2.3.4:443?type=xhttp&path=%2Fx&host=x.com&mode=auto&security=tls#X"
    ));
    assert_eq!(str_at(&x, "network"), "xhttp");
    assert_eq!(str_at(&x, "xhttp-opts.path"), "/x");
    assert_eq!(str_at(&x, "xhttp-opts.mode"), "auto");

    let hu = one(&format!(
        "vless://{UUID}@1.2.3.4:80?type=httpupgrade&path=%2Fhu&host=hu.com&security=none#HU"
    ));
    assert_eq!(str_at(&hu, "network"), "ws");
    assert_eq!(get(&hu, "ws-opts.v2ray-http-upgrade").as_bool(), Some(true));
    assert!(hu.get("tls").is_none());

    let h2 = one(&format!(
        "vless://{UUID}@1.2.3.4:443?type=http&path=%2Fh2&host=h2.com&security=tls#H2"
    ));
    assert_eq!(str_at(&h2, "network"), "h2");
    assert_eq!(str_at(&h2, "h2-opts.path"), "/h2");
}

#[test]
fn vless_insecure_and_ipv6() {
    let m = one(&format!(
        "vless://{UUID}@[2001:db8::1]:443?security=tls&allowInsecure=1&sni=v6.example.com#v6"
    ));
    assert_eq!(str_at(&m, "server"), "2001:db8::1");
    assert_eq!(get(&m, "skip-cert-verify").as_bool(), Some(true));
}

#[test]
fn vless_unsupported_transport_is_an_error() {
    let err = parse_proxy_uri(&format!("vless://{UUID}@1.2.3.4:443?type=kcp#KCP")).unwrap_err();
    assert!(format!("{err:#}").contains("kcp"));
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------

#[test]
fn trojan_fp_is_client_fingerprint_not_cert_pin() {
    let m = one(
        "trojan://p%40ss@1.2.3.4:443?security=tls&sni=t.example.com&fp=chrome&type=ws&path=%2Ftr&host=t.example.com&allowInsecure=1#Trojan%20WS",
    );
    assert_eq!(str_at(&m, "password"), "p@ss");
    assert_eq!(str_at(&m, "sni"), "t.example.com");
    assert_eq!(str_at(&m, "client-fingerprint"), "chrome");
    assert!(m.get("fingerprint").is_none(), "fp must not become the certificate pin");
    assert!(m.get("tls").is_none(), "trojan is always TLS");
    assert_eq!(str_at(&m, "network"), "ws");
    assert_eq!(get(&m, "skip-cert-verify").as_bool(), Some(true));
}

#[test]
fn trojan_grpc_and_sni_from_host() {
    let m = one("trojan://secret@104.21.0.1:443/?type=grpc&serviceName=tg&host=cdn.t.com#T");
    assert_eq!(str_at(&m, "grpc-opts.grpc-service-name"), "tg");
    assert_eq!(str_at(&m, "sni"), "cdn.t.com");
}

// ---------------------------------------------------------------------------
// Shadowsocks / ShadowsocksR
// ---------------------------------------------------------------------------

#[test]
fn ss_sip002_base64_userinfo() {
    let m = one(&format!("ss://{}@1.2.3.4:8388#SS%201", b64("aes-256-gcm:pa:ss")));
    assert_eq!(str_at(&m, "name"), "SS 1");
    assert_eq!(str_at(&m, "cipher"), "aes-256-gcm");
    assert_eq!(str_at(&m, "password"), "pa:ss");
    assert_eq!(get(&m, "udp").as_bool(), Some(true));
}

#[test]
fn ss_2022_percent_encoded_userinfo() {
    let m =
        one("ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@5.6.7.8:443#ss2022");
    assert_eq!(str_at(&m, "cipher"), "2022-blake3-aes-128-gcm");
    assert_eq!(str_at(&m, "password"), "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=");
}

#[test]
fn ss_legacy_fully_encoded() {
    let m = one(&format!(
        "ss://{}#Legacy",
        b64("chacha20-ietf-poly1305:secret@9.9.9.9:443")
    ));
    assert_eq!(str_at(&m, "server"), "9.9.9.9");
    assert_eq!(str_at(&m, "cipher"), "chacha20-ietf-poly1305");
    assert_eq!(str_at(&m, "password"), "secret");
}

#[test]
fn ss_obfs_and_v2ray_plugins() {
    let obfs = one(&format!(
        "ss://{}@1.2.3.4:443/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dbing.com#obfs",
        b64("aes-128-gcm:x")
    ));
    assert_eq!(str_at(&obfs, "plugin"), "obfs");
    assert_eq!(str_at(&obfs, "plugin-opts.mode"), "tls");
    assert_eq!(str_at(&obfs, "plugin-opts.host"), "bing.com");

    let v2 = one(&format!(
        "ss://{}@1.2.3.4:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dv.com%3Bpath%3D%2Fv#v2",
        b64("aes-128-gcm:x")
    ));
    assert_eq!(str_at(&v2, "plugin"), "v2ray-plugin");
    assert_eq!(str_at(&v2, "plugin-opts.mode"), "websocket");
    assert_eq!(str_at(&v2, "plugin-opts.host"), "v.com");
    assert_eq!(str_at(&v2, "plugin-opts.path"), "/v");
    assert_eq!(get(&v2, "plugin-opts.tls").as_bool(), Some(true));
}

#[test]
fn ssr_link() {
    let pass = general_purpose::URL_SAFE_NO_PAD.encode("pwd");
    let remarks = general_purpose::URL_SAFE_NO_PAD.encode("SSR Node");
    let body =
        format!("1.2.3.4:8989:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{pass}/?remarks={remarks}&obfsparam=");
    let m = one(&format!("ssr://{}", general_purpose::URL_SAFE_NO_PAD.encode(body)));
    assert_eq!(str_at(&m, "name"), "SSR Node");
    assert_eq!(str_at(&m, "protocol"), "auth_aes128_md5");
    assert_eq!(str_at(&m, "cipher"), "aes-256-cfb");
    assert_eq!(str_at(&m, "obfs"), "tls1.2_ticket_auth");
    assert_eq!(str_at(&m, "password"), "pwd");
}

// ---------------------------------------------------------------------------
// Hysteria / Hysteria2 / TUIC / AnyTLS / SOCKS / WireGuard
// ---------------------------------------------------------------------------

#[test]
fn hysteria2_port_hopping_and_obfs() {
    let m = one(
        "hy2://pa%24s@h.example.com:443,20000-30000/?sni=h.example.com&obfs=salamander&obfs-password=ob&insecure=1#HY2",
    );
    assert_eq!(str_at(&m, "type"), "hysteria2");
    assert_eq!(get(&m, "port").as_u64(), Some(443));
    assert_eq!(str_at(&m, "ports"), "443,20000-30000");
    assert_eq!(str_at(&m, "password"), "pa$s");
    assert_eq!(str_at(&m, "obfs"), "salamander");
    assert_eq!(get(&m, "skip-cert-verify").as_bool(), Some(true));

    let plain = one("hysteria2://pw@1.2.3.4:8443?sni=a.com&obfs=none#plain");
    assert!(plain.get("obfs").is_none());
}

#[test]
fn hysteria_v1() {
    let m = one(
        "hysteria://1.2.3.4:443?protocol=udp&auth=pw&peer=a.com&insecure=1&upmbps=20&downmbps=100&alpn=hysteria#HY1",
    );
    assert_eq!(str_at(&m, "auth-str"), "pw");
    assert_eq!(str_at(&m, "sni"), "a.com");
    assert_eq!(str_at(&m, "up"), "20");
    assert_eq!(str_at(&m, "down"), "100");
}

#[test]
fn tuic_v5() {
    let m = one(&format!(
        "tuic://{UUID}:pw@1.2.3.4:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.com&allow_insecure=1#TUIC"
    ));
    assert_eq!(str_at(&m, "uuid"), UUID);
    assert_eq!(str_at(&m, "password"), "pw");
    assert_eq!(str_at(&m, "congestion-controller"), "bbr");
    assert_eq!(str_at(&m, "udp-relay-mode"), "native");
    assert_eq!(get(&m, "skip-cert-verify").as_bool(), Some(true));
}

#[test]
fn anytls_socks_wireguard() {
    let a = one("anytls://pw@1.2.3.4:443/?sni=a.com&insecure=1#Any");
    assert_eq!(str_at(&a, "type"), "anytls");
    assert_eq!(str_at(&a, "password"), "pw");

    let s5 = one(&format!("socks://{}@1.2.3.4:1080#S5", b64("user:pass")));
    assert_eq!(str_at(&s5, "type"), "socks5");
    assert_eq!(str_at(&s5, "username"), "user");
    assert_eq!(str_at(&s5, "password"), "pass");

    let wg = one(
        "wireguard://cPrivateKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8a36%3A%3A1%2F128&reserved=1%2C2%2C3&mtu=1280#WARP",
    );
    assert_eq!(
        str_at(&wg, "private-key"),
        "cPrivateKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(
        str_at(&wg, "public-key"),
        "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    );
    assert_eq!(str_at(&wg, "ip"), "172.16.0.2");
    assert_eq!(str_at(&wg, "ipv6"), "2606:4700:110:8a36::1");
    assert_eq!(get(&wg, "reserved").as_sequence().unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

fn sample_links() -> Vec<String> {
    vec![
        format!("vless://{UUID}@1.1.1.1:443?security=tls&sni=a.com&type=ws&path=%2F#Node1"),
        "trojan://pass@2.2.2.2:443?sni=b.com#Node2".to_owned(),
        format!("ss://{}@3.3.3.3:8388#Node3", b64("aes-128-gcm:pw")),
    ]
}

#[test]
fn base64_subscription_with_line_wrapping_bom_and_crlf() {
    let encoded = b64(&sample_links().join("\r\n"));
    // MIME-style 76-column wrapping plus a UTF-8 BOM
    let wrapped: Vec<String> = encoded
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    let body = format!("\u{feff}{}\n", wrapped.join("\n"));
    let cfg = convert(&body);
    assert_eq!(proxy_names(&cfg), vec!["Node1", "Node2", "Node3"]);
}

#[test]
fn url_safe_unpadded_subscription() {
    let body = general_purpose::URL_SAFE_NO_PAD.encode(sample_links().join("\n"));
    assert_eq!(proxy_names(&convert(&body)).len(), 3);
}

#[test]
fn plain_text_subscription_skips_junk_and_bad_links() {
    let body = format!(
        "# provider header\n{}\nnot a link\nhttp://example.com/info\nvless://broken\n{}\n{}\n",
        sample_links()[0],
        sample_links()[1],
        sample_links()[2]
    );
    assert_eq!(proxy_names(&convert(&body)).len(), 3);
}

#[test]
fn several_links_on_one_line_and_names_with_spaces() {
    let line = format!(
        "{} trojan://pw@4.4.4.4:443?sni=d.com#My Server Name {}",
        sample_links()[0],
        sample_links()[1]
    );
    let names = proxy_names(&convert(&line));
    assert_eq!(names, vec!["Node1", "My Server Name", "Node2"]);
}

#[test]
fn all_links_invalid_is_a_clear_error() {
    let err = try_convert_txt_to_yaml("vless://nohost\nvmess://%%%").unwrap_err();
    assert!(format!("{err:#}").contains("none could be imported"), "{err:#}");
}

#[test]
fn not_links_returns_none() {
    assert!(try_convert_txt_to_yaml("proxies:\n  - name: a\n").unwrap().is_none());
    assert!(try_convert_txt_to_yaml("hello world").unwrap().is_none());
}

#[test]
fn duplicate_and_empty_names_are_made_unique() {
    let body = [
        "trojan://p@1.1.1.1:443?sni=a.com#DE",
        "trojan://p@2.2.2.2:443?sni=b.com#DE",
        "trojan://p@3.3.3.3:443?sni=c.com#DE",
    ]
    .join("\n");
    assert_eq!(proxy_names(&convert(&body)), vec!["DE", "DE #2", "DE #3"]);
}

#[test]
fn generated_config_routes_through_proxy_with_lan_bypass() {
    let cfg = convert(&sample_links().join("\n"));
    assert_eq!(cfg["find-process-mode"].as_str(), Some("always"));
    let rules: Vec<&str> = cfg["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|r| r.as_str())
        .collect();
    assert!(rules.iter().any(|r| r.starts_with("IP-CIDR,192.168.0.0/16,DIRECT")));
    assert_eq!(rules.last(), Some(&"MATCH,Manual"));
    assert!(
        rules[..rules.len() - 1].iter().all(|r| r.contains(",DIRECT")),
        "everything above the catch-all must be a DIRECT bypass"
    );
    let groups = cfg["proxy-groups"].as_sequence().unwrap();
    let manual = groups
        .iter()
        .find(|g| g["name"].as_str() == Some(MANUAL_GROUP))
        .unwrap();
    let members: Vec<&str> = manual["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .collect();
    assert_eq!(members.first(), Some(&AUTO_GROUP));
    assert!(members.contains(&"DIRECT"));
    assert!(members.contains(&"Node2"));
}

// ---------------------------------------------------------------------------
// normalize_subscription / Clash YAML handling
// ---------------------------------------------------------------------------

#[test]
fn html_and_singbox_bodies_are_rejected_with_a_reason() {
    let html = normalize_subscription("<!DOCTYPE html><html><body>Access denied</body></html>").unwrap_err();
    assert!(html.to_string().contains("web page"));
    let json = normalize_subscription(r#"{"log":{},"outbounds":[{"type":"vless"}]}"#).unwrap_err();
    assert!(json.to_string().contains("sing-box"));
}

#[test]
fn proxies_only_yaml_gets_groups_and_rules() {
    let yaml = "proxies:\n  - {name: A, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n  - {name: B, type: ss, server: 2.2.2.2, port: 2, cipher: aes-128-gcm, password: x}\n";
    let out: Value = serde_yaml_ng::from_str(&normalize_subscription(yaml).unwrap()).unwrap();
    assert_eq!(out["proxy-groups"].as_sequence().unwrap().len(), 2);
    assert_eq!(
        out["rules"].as_sequence().unwrap().last().unwrap().as_str(),
        Some("MATCH,Manual")
    );
}

#[test]
fn groups_without_rules_target_the_first_group() {
    let yaml = "proxies:\n  - {name: A, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\nproxy-groups:\n  - {name: PROXY, type: select, proxies: [A]}\n";
    let out: Value = serde_yaml_ng::from_str(&normalize_subscription(yaml).unwrap()).unwrap();
    assert_eq!(
        out["rules"].as_sequence().unwrap().last().unwrap().as_str(),
        Some("MATCH,PROXY")
    );
    assert_eq!(out["proxy-groups"].as_sequence().unwrap().len(), 1);
}

#[test]
fn provider_only_yaml_gets_groups_using_the_provider() {
    let yaml = "proxy-providers:\n  sub:\n    type: http\n    url: https://example.com/sub\n    path: ./sub.yaml\n";
    let out: Value = serde_yaml_ng::from_str(&normalize_subscription(yaml).unwrap()).unwrap();
    let groups = out["proxy-groups"].as_sequence().unwrap();
    assert!(groups.iter().all(|g| g["use"][0].as_str() == Some("sub")));
}

#[test]
fn complete_yaml_is_left_untouched() {
    let yaml = "proxies:\n- name: A\n  type: ss\nproxy-groups:\n- name: G\n  type: select\n  proxies:\n  - A\nrules:\n- MATCH,G\n";
    assert_eq!(normalize_subscription(yaml).unwrap(), yaml);
}

#[test]
fn dedupe_clash_yaml_rewrites_group_refs_positionally() {
    let yaml = r#"
proxy-groups:
- name: Auto
  type: url-test
  proxies: [A, CZ, B, CZ]
proxies:
- {name: A, type: ss, server: 1.1.1.1, port: 1}
- {name: CZ, type: ss, server: 2.2.2.2, port: 2}
- {name: B, type: ss, server: 3.3.3.3, port: 3}
- {name: CZ, type: ss, server: 4.4.4.4, port: 4}
"#;
    let out: Value = serde_yaml_ng::from_str(&dedupe_clash_yaml(yaml).unwrap().unwrap()).unwrap();
    let refs: Vec<&str> = out["proxy-groups"][0]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(refs, vec!["A", "CZ", "B", "CZ #2"]);
    assert!(
        dedupe_clash_yaml("proxies:\n  - {name: A, type: ss}\n")
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// End-to-end: the mihomo core must accept what we generate.
//
// Runs only when SR_VERGE_MIHOMO points at a mihomo binary, e.g.
//   SR_VERGE_MIHOMO=/path/to/verge-mihomo cargo test proxy_parser
// ---------------------------------------------------------------------------

fn every_format_sample() -> String {
    let vmess_json = format!(
        r#"{{"ps":"vmess-ws","add":"1.2.3.4","port":"443","id":"{UUID}","aid":"0","net":"ws","host":"h.com","path":"/p?ed=2048","tls":"tls"}}"#
    );
    let ssr_body = format!(
        "1.2.3.4:8989:origin:aes-256-cfb:plain:{}/?remarks={}",
        general_purpose::URL_SAFE_NO_PAD.encode("pwd"),
        general_purpose::URL_SAFE_NO_PAD.encode("ssr")
    );
    [
        format!("vmess://{}", b64(&vmess_json)),
        format!("vmess://{UUID}@1.2.3.4:443?type=grpc&serviceName=g&security=tls#vmess-aead"),
        format!("vless://{UUID}@1.2.3.4:443/?type=ws&host=h.com&path=%2F%3Fed%3D2048&security=tls#vless-ws"),
        format!("vless://{UUID}@1.2.3.4:443?security=reality&sni=www.speedtest.net&pbk=Q8TdyS_MSNI0dHTMuNKNG9ZyxZsfeCHAJT0zbVhyy0E&sid=6ba8&flow=xtls-rprx-vision&type=tcp#vless-reality"),
        format!("vless://{UUID}@1.2.3.4:443?type=grpc&serviceName=g&security=tls&sni=a.com#vless-grpc"),
        format!("vless://{UUID}@1.2.3.4:443?type=xhttp&path=%2Fx&mode=auto&security=tls#vless-xhttp"),
        format!("vless://{UUID}@1.2.3.4:80?type=httpupgrade&path=%2Fh&host=h.com#vless-httpupgrade"),
        format!("vless://{UUID}@1.2.3.4:443?type=tcp&headerType=http&host=h.com#vless-tcp-http"),
        "trojan://pw@1.2.3.4:443?sni=t.com&fp=chrome&type=ws&path=%2Ft#trojan-ws".to_owned(),
        format!("ss://{}@1.2.3.4:8388#ss", b64("aes-256-gcm:pw")),
        "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@1.2.3.4:443#ss-2022".to_owned(),
        format!("ss://{}@1.2.3.4:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Db.com#ss-obfs", b64("aes-128-gcm:x")),
        format!("ssr://{}", general_purpose::URL_SAFE_NO_PAD.encode(ssr_body)),
        "hysteria2://pw@1.2.3.4:443,20000-30000/?sni=a.com&obfs=salamander&obfs-password=o#hy2".to_owned(),
        "hysteria://1.2.3.4:443?auth=pw&peer=a.com&upmbps=20&downmbps=100#hy1".to_owned(),
        format!("tuic://{UUID}:pw@1.2.3.4:443?congestion_control=bbr&alpn=h3&sni=t.com#tuic"),
        "anytls://pw@1.2.3.4:443?sni=a.com#anytls".to_owned(),
        format!("socks://{}@1.2.3.4:1080#socks", b64("u:p")),
        "wireguard://yAnz5TF%2BlXXJte14tji3zlMNq%2BhdWr4bBPV7%2FLMcUmE%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32&reserved=1%2C2%2C3&mtu=1280#wg".to_owned(),
    ]
    .join("\n")
}

#[test]
fn every_supported_format_is_converted() {
    let cfg = convert(&b64(&every_format_sample()));
    assert_eq!(proxy_names(&cfg).len(), every_format_sample().lines().count());
}

#[test]
fn mihomo_accepts_generated_config() {
    let Ok(bin) = std::env::var("SR_VERGE_MIHOMO") else {
        eprintln!("SR_VERGE_MIHOMO not set, skipping mihomo validation");
        return;
    };
    let yaml = try_convert_txt_to_yaml(&b64(&every_format_sample())).unwrap().unwrap();
    let dir = std::env::temp_dir().join(format!("sr-verge-parser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.yaml");
    std::fs::write(&file, &yaml).unwrap();
    let out = std::process::Command::new(bin)
        .arg("-t")
        .arg("-d")
        .arg(&dir)
        .arg("-f")
        .arg(&file)
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "mihomo rejected the config:\n{log}\n---\n{yaml}");
}

// ---------------------------------------------------------------------------
// Dropping servers the core rejects
// ---------------------------------------------------------------------------

#[test]
fn rejected_proxy_index_reads_mihomo_output() {
    let log = r#"level=error msg="proxy 10: ss 1.2.3.4:443 cipher: 2022-blake3-aes-128-gcm initialize error: bad key length""#;
    assert_eq!(rejected_proxy_index(log), Some(10));
    assert_eq!(rejected_proxy_index("proxy group[0]: 'X' not found"), None);
    assert_eq!(
        rejected_proxy_index("rules[3] [MATCH,Nope] error: proxy [Nope] not found"),
        None
    );
}

#[test]
fn remove_proxy_drops_node_and_group_references() {
    let yaml = convert(&sample_links().join("\n"));
    let yaml = serde_yaml_ng::to_string(&yaml).unwrap();
    let (out, name) = remove_proxy(&yaml, 1).unwrap();
    assert_eq!(name, "Node2");
    let cfg: Value = serde_yaml_ng::from_str(&out).unwrap();
    assert_eq!(proxy_names(&cfg), vec!["Node1", "Node3"]);
    for group in cfg["proxy-groups"].as_sequence().unwrap() {
        assert!(
            group["proxies"]
                .as_sequence()
                .unwrap()
                .iter()
                .all(|p| p.as_str() != Some("Node2"))
        );
    }
}

#[test]
fn remove_last_proxy_is_an_error() {
    let yaml = serde_yaml_ng::to_string(&convert(&sample_links()[0])).unwrap();
    assert!(remove_proxy(&yaml, 0).is_err());
}

fn mihomo_test(bin: &str, yaml: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("sr-verge-prune-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.yaml");
    std::fs::write(&file, yaml).unwrap();
    let out = std::process::Command::new(bin)
        .args(["-t", "-d"])
        .arg(&dir)
        .arg("-f")
        .arg(&file)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), log)
}

/// Same loop as `core::import_check`, driven by the real core binary.
#[test]
fn mihomo_broken_nodes_are_pruned_and_the_rest_load() {
    let Ok(bin) = std::env::var("SR_VERGE_MIHOMO") else {
        eprintln!("SR_VERGE_MIHOMO not set, skipping mihomo validation");
        return;
    };
    let links = [
        sample_links()[0].clone(),
        // 32-byte key with a cipher that needs 16 bytes: the core refuses it
        "ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@1.2.3.4:443#BadKey"
            .to_owned(),
        sample_links()[1].clone(),
        format!("ss://{}@1.2.3.4:443#BadCipher", b64("no-such-cipher:pw")),
        sample_links()[2].clone(),
    ];
    let mut yaml = try_convert_txt_to_yaml(&links.join("\n")).unwrap().unwrap();
    let mut dropped = Vec::new();
    loop {
        let (ok, log) = mihomo_test(&bin, &yaml);
        if ok {
            break;
        }
        let index = rejected_proxy_index(&log).unwrap_or_else(|| panic!("not a proxy error:\n{log}"));
        let (next, name) = remove_proxy(&yaml, index).unwrap();
        dropped.push(name);
        yaml = next;
        assert!(dropped.len() <= 2, "pruned too much: {dropped:?}");
    }
    assert_eq!(dropped, vec!["BadKey", "BadCipher"]);
    let cfg: Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(proxy_names(&cfg), vec!["Node1", "Node2", "Node3"]);
}

// ---------------------------------------------------------------------------
// XHTTP (Xray share-link standard)
// ---------------------------------------------------------------------------

/// A real provider link (uuid replaced). Every node from this subscription
/// timed out: the `?=` in the path reached mihomo, which requested
/// `/search%3F=/<session>` while the server serves `/search/<session>`.
const XHTTP_PROVIDER_LINK: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ir.example.com:2083?alpn=h2%2Chttp%2F1.1%2Ch3&encryption=none&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D&fp=chrome&host=IR.Example.Com&mode=auto&path=%2Fsearch%3F%3D&security=tls&sni=IR.Example.com&type=xhttp&x_padding_bytes=100-1000#%F0%9F%87%A9%F0%9F%87%AA%20MAX%20~%20DE";

#[test]
fn xhttp_path_query_is_stripped_like_xray() {
    let m = one(XHTTP_PROVIDER_LINK);
    assert_eq!(str_at(&m, "network"), "xhttp");
    assert_eq!(str_at(&m, "xhttp-opts.path"), "/search");
    assert_eq!(str_at(&m, "xhttp-opts.host"), "IR.Example.Com");
    assert_eq!(str_at(&m, "xhttp-opts.mode"), "auto");
    assert_eq!(str_at(&m, "xhttp-opts.x-padding-bytes"), "100-1000");
    assert_eq!(str_at(&m, "servername"), "IR.Example.com");
    assert_eq!(str_at(&m, "name"), "🇩🇪 MAX ~ DE");
}

#[test]
fn xhttp_extra_settings_are_kept() {
    let extra = r#"{"headers":{"X-Test":"1"},"noGRPCHeader":true,"xPaddingBytes":"200-400","scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":"10-50","xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":30}}"#;
    let link = format!(
        "vless://{UUID}@1.2.3.4:443?type=xhttp&security=tls&sni=a.com&path=%2Fx&mode=packet-up&extra={}#X",
        percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
    );
    let m = one(&link);
    assert_eq!(str_at(&m, "xhttp-opts.path"), "/x");
    assert_eq!(str_at(&m, "xhttp-opts.mode"), "packet-up");
    assert_eq!(str_at(&m, "xhttp-opts.headers.X-Test"), "1");
    assert_eq!(get(&m, "xhttp-opts.no-grpc-header").as_bool(), Some(true));
    assert_eq!(str_at(&m, "xhttp-opts.x-padding-bytes"), "200-400");
    assert_eq!(str_at(&m, "xhttp-opts.sc-max-each-post-bytes"), "1000000");
    assert_eq!(str_at(&m, "xhttp-opts.sc-min-posts-interval-ms"), "10-50");
    assert_eq!(str_at(&m, "xhttp-opts.reuse-settings.max-concurrency"), "16-32");
    assert_eq!(
        get(&m, "xhttp-opts.reuse-settings.h-keep-alive-period").as_u64(),
        Some(30)
    );
}

#[test]
fn mihomo_accepts_provider_xhttp_config() {
    let Ok(bin) = std::env::var("SR_VERGE_MIHOMO") else {
        eprintln!("SR_VERGE_MIHOMO not set, skipping mihomo validation");
        return;
    };
    let yaml = try_convert_txt_to_yaml(XHTTP_PROVIDER_LINK).unwrap().unwrap();
    let (ok, log) = mihomo_test(&bin, &yaml);
    assert!(ok, "mihomo rejected the config:\n{log}\n---\n{yaml}");
}
