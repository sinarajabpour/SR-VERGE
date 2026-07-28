use clash_verge_logging::{Type, logging};

use super::use_lowercase;
use serde_yaml_ng::{self, Mapping, Value};

fn deep_merge(a: &mut Value, b: Value) {
    match (a, b) {
        (Value::Mapping(a_map), Value::Mapping(b_map)) => {
            for (key, value) in b_map {
                if let Some(existing) = a_map.get_mut(&key) {
                    deep_merge(existing, value);
                } else {
                    a_map.insert(key, value);
                }
            }
        }
        (a, b) => *a = b,
    }
}

/// Splits `prepend-<field>` / `append-<field>` directives out of a merge
/// document, returning them alongside the remaining plain keys.
///
/// These are not real Clash fields: they instruct the merge to add entries to
/// an existing list rather than replace it. They must be removed here, because
/// a plain deep merge would otherwise copy them into the final config verbatim
/// and the core would silently ignore them.
fn split_seq_directives(merge: Mapping) -> (Mapping, Vec<(Value, bool, Vec<Value>)>) {
    let mut plain = Mapping::new();
    let mut directives = Vec::new();

    for (key, value) in merge {
        let name = key.as_str().unwrap_or_default();
        let split = name
            .strip_prefix("prepend-")
            .map(|field| (field, true))
            .or_else(|| name.strip_prefix("append-").map(|field| (field, false)));

        match (split, value) {
            (Some((field, is_prepend)), Value::Sequence(items)) => {
                directives.push((Value::String(field.to_owned()), is_prepend, items));
            }
            // A prepend-/append- key whose value is not a list is malformed;
            // drop it rather than leaking it into the config.
            (Some(_), _) => {
                logging!(warn, Type::Core, "ignoring non-list merge directive: {name}");
            }
            (None, value) => {
                plain.insert(key, value);
            }
        }
    }

    (plain, directives)
}

pub fn use_merge(merge: &Mapping, config: Mapping) -> Mapping {
    let mut config = Value::from(config);
    let merge = use_lowercase(merge);
    let (plain, directives) = split_seq_directives(merge);

    deep_merge(&mut config, Value::from(plain));

    if let Some(map) = config.as_mapping_mut() {
        for (field, is_prepend, items) in directives {
            let existing = map
                .get(&field)
                .and_then(Value::as_sequence)
                .cloned()
                .unwrap_or_default();

            let merged = if is_prepend {
                items.into_iter().chain(existing).collect()
            } else {
                existing.into_iter().chain(items).collect()
            };

            map.insert(field, Value::Sequence(merged));
        }
    }

    config.as_mapping().cloned().unwrap_or_else(|| {
        logging!(
            error,
            Type::Core,
            "Failed to convert merged config to mapping, using empty mapping"
        );
        Mapping::new()
    })
}

#[test]
fn test_merge() -> anyhow::Result<()> {
    let merge = r"
    prepend-rules:
      - prepend
      - 1123123
    append-rules:
      - append
    prepend-proxies:
      - 9999
    append-proxies:
      - 1111
    rules:
      - replace
    proxy-groups: 
      - 123781923810
    tun:
      enable: true
    dns:
      enable: true
  ";

    let config = r"
    rules:
      - aaaaa
    script1: test
  ";

    let merge = serde_yaml_ng::from_str::<Mapping>(merge)?;
    let config = serde_yaml_ng::from_str::<Mapping>(config)?;

    let _ = serde_yaml_ng::to_string(&use_merge(&merge, config))?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod directive_tests {
    use super::*;

    fn merge_str(merge: &str, config: &str) -> Mapping {
        use_merge(
            &serde_yaml_ng::from_str::<Mapping>(merge).unwrap(),
            serde_yaml_ng::from_str::<Mapping>(config).unwrap(),
        )
    }

    fn rules(map: &Mapping) -> Vec<String> {
        map["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn prepend_rules_go_above_existing_rules() {
        let out = merge_str(
            "prepend-rules:\n  - DOMAIN-SUFFIX,ir,DIRECT\n  - GEOIP,IR,DIRECT\n",
            "rules:\n  - MATCH,Proxy\n",
        );
        assert_eq!(
            rules(&out),
            ["DOMAIN-SUFFIX,ir,DIRECT", "GEOIP,IR,DIRECT", "MATCH,Proxy"]
        );
        // The directive itself must not survive into the config.
        assert!(!out.contains_key("prepend-rules"));
    }

    #[test]
    fn append_rules_go_below_existing_rules() {
        let out = merge_str(
            "append-rules:\n  - MATCH,Proxy\n",
            "rules:\n  - DOMAIN-SUFFIX,ir,DIRECT\n",
        );
        assert_eq!(rules(&out), ["DOMAIN-SUFFIX,ir,DIRECT", "MATCH,Proxy"]);
        assert!(!out.contains_key("append-rules"));
    }

    #[test]
    fn directives_work_when_the_field_is_absent() {
        let out = merge_str("prepend-rules:\n  - MATCH,Proxy\n", "mode: rule\n");
        assert_eq!(rules(&out), ["MATCH,Proxy"]);
    }

    #[test]
    fn plain_keys_still_replace_and_deep_merge() {
        let out = merge_str(
            "rules:\n  - MATCH,Direct\ntun:\n  enable: true\n",
            "rules:\n  - MATCH,Proxy\ntun:\n  stack: gvisor\n",
        );
        // A plain `rules` key replaces rather than appends.
        assert_eq!(rules(&out), ["MATCH,Direct"]);
        // Nested maps still merge instead of clobbering.
        assert_eq!(out["tun"]["enable"].as_bool(), Some(true));
        assert_eq!(out["tun"]["stack"].as_str(), Some("gvisor"));
    }

    #[test]
    fn malformed_directive_is_dropped_not_leaked() {
        let out = merge_str("prepend-rules: not-a-list\n", "rules:\n  - MATCH,Proxy\n");
        assert_eq!(rules(&out), ["MATCH,Proxy"]);
        assert!(!out.contains_key("prepend-rules"));
    }
}
