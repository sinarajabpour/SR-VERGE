//! End-to-end profile flow without the GUI: import subscriptions from a local
//! HTTP server, select a profile, update it, and delete it. Runs against the
//! real `PrfItem::from_url` / `IProfiles` code with the app in portable mode,
//! so profiles are written next to the test binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{Config, IProfiles, PrfItem, profiles};
use crate::utils::dirs;
use base64::{Engine as _, engine::general_purpose};
use serde_yaml_ng::Value;
use smartstring::alias::String;
use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn links(count: usize) -> std::string::String {
    (1..=count)
        .map(|i| format!("vless://{UUID}@10.0.0.{i}:443/?type=ws&path=%2F&security=tls&sni=n{i}.example.com#Node{i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Minimal HTTP server. `/sub` serves a Base64 share-link subscription whose
/// node count is `2 + version`, so an update is observable.
fn serve(version: Arc<AtomicUsize>) -> std::string::String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = std::string::String::new();
            let _ = reader.read_line(&mut request_line);
            // drain headers
            let mut line = std::string::String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_owned();
            let (headers, body) = match path.as_str() {
                "/sub" => (
                    "Subscription-Userinfo: upload=1024; download=2048; total=10737418240; expire=1893456000\r\n\
                     Profile-Update-Interval: 12\r\n\
                     Content-Disposition: attachment; filename*=UTF-8''My%20Sub\r\n",
                    general_purpose::STANDARD.encode(links(2 + version.load(Ordering::SeqCst))),
                ),
                "/clash" => (
                    "",
                    "proxies:\n  - {name: SS1, type: ss, server: 10.1.0.1, port: 8388, cipher: aes-128-gcm, password: pw}\n"
                        .to_owned(),
                ),
                "/blocked" => ("", "<!DOCTYPE html><html><body>blocked</body></html>".to_owned()),
                _ => ("", "not found".to_owned()),
            };
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

fn proxy_names(yaml: &str) -> Vec<std::string::String> {
    let cfg: Value = serde_yaml_ng::from_str(yaml).unwrap();
    cfg["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn profile_file(item: &PrfItem) -> std::string::String {
    let path = dirs::app_profiles_dir()
        .unwrap()
        .join(item.file.as_ref().unwrap().as_str());
    tokio::fs::read_to_string(path).await.unwrap()
}

async fn current_profiles() -> IProfiles {
    *Config::profiles().await.latest_arc().as_ref().clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn import_select_update_and_delete_profiles() {
    // portable mode: everything lives under <test binary dir>/.config/<app id>
    dirs::PORTABLE_FLAG.get_or_init(|| true);
    let home = dirs::app_home_dir().unwrap();
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(dirs::app_profiles_dir().unwrap()).unwrap();

    let version = Arc::new(AtomicUsize::new(0));
    let base = serve(Arc::clone(&version));

    // 1. import a Base64 share-link subscription
    let mut sub = PrfItem::from_url(&format!("{base}/sub"), None, None, None)
        .await
        .expect("base64 subscription should import");
    assert_eq!(sub.name.as_deref(), Some("My Sub"), "name from Content-Disposition");
    let extra = sub.extra.expect("subscription-userinfo should be parsed");
    assert_eq!(
        (extra.upload, extra.download, extra.total),
        (1024, 2048, 10_737_418_240)
    );
    assert_eq!(sub.option.as_ref().and_then(|o| o.update_interval), Some(12 * 60));
    let data = sub.file_data.clone().unwrap();
    assert_eq!(proxy_names(&data), vec!["Node1", "Node2"]);
    assert!(
        data.contains("MATCH,Manual"),
        "converted profile must route through the proxy"
    );
    profiles::profiles_append_item_safe(&mut sub).await.unwrap();
    let sub_uid: String = sub.uid.clone().unwrap();

    // the first imported profile becomes the current one
    assert_eq!(current_profiles().await.get_current(), Some(&sub_uid));
    assert_eq!(proxy_names(&profile_file(&sub).await), vec!["Node1", "Node2"]);

    // 2. import a Clash YAML that only lists proxies
    let mut clash = PrfItem::from_url(&format!("{base}/clash"), None, None, None)
        .await
        .expect("proxies-only clash yaml should import");
    profiles::profiles_append_item_safe(&mut clash).await.unwrap();
    let clash_uid: String = clash.uid.clone().unwrap();
    assert_eq!(
        current_profiles().await.get_current(),
        Some(&sub_uid),
        "importing must not switch"
    );

    // 3. select the second profile
    Config::profiles().await.edit_draft(|d| {
        d.patch_config(&IProfiles {
            current: Some(clash_uid.clone()),
            items: None,
        })
    });
    Config::profiles().await.apply();
    let selected = current_profiles().await;
    assert_eq!(selected.get_current(), Some(&clash_uid));
    let mapping = selected.current_mapping().await.unwrap();
    let rules = mapping.get("rules").and_then(|r| r.as_sequence()).unwrap();
    assert_eq!(
        rules.last().and_then(|r| r.as_str()),
        Some("MATCH,Manual"),
        "groups and rules added to the proxies-only config"
    );
    // selecting an unknown uid is ignored
    Config::profiles().await.edit_draft(|d| {
        d.patch_config(&IProfiles {
            current: Some("nope".into()),
            items: None,
        })
    });
    Config::profiles().await.apply();
    assert_eq!(current_profiles().await.get_current(), Some(&clash_uid));

    // 4. update the first profile: the provider now serves more nodes
    version.store(2, Ordering::SeqCst);
    let mut updated = PrfItem::from_url(&format!("{base}/sub"), None, None, sub.option.as_ref())
        .await
        .unwrap();
    profiles::profiles_draft_update_item_safe(&sub_uid, &mut updated)
        .await
        .unwrap();
    let after = current_profiles().await;
    let stored = after.get_item(&sub_uid).unwrap();
    assert_eq!(stored.file, sub.file, "an update keeps the profile's file");
    assert_eq!(
        proxy_names(&profile_file(stored).await),
        vec!["Node1", "Node2", "Node3", "Node4"]
    );
    assert_eq!(
        after.get_current(),
        Some(&clash_uid),
        "updating must not switch profile"
    );

    // 5. a blocked link fails with an explanation instead of "invalid yaml"
    let err = PrfItem::from_url(&format!("{base}/blocked"), None, None, None)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("web page"), "{err:#}");

    // 6. deleting the current profile falls back to the remaining one
    let deleted_current = profiles::profiles_delete_item_safe(&clash_uid).await.unwrap();
    assert!(deleted_current);
    let left = current_profiles().await;
    assert_eq!(left.get_current(), Some(&sub_uid));
    assert!(left.get_item(&clash_uid).is_err());
    let clash_file = dirs::app_profiles_dir().unwrap().join(clash.file.unwrap().as_str());
    assert!(!clash_file.exists(), "the deleted profile's file is removed");

    let _ = std::fs::remove_dir_all(&home);
}
