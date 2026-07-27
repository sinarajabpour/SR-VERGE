//! Some config file template

/// template for new a profile item
pub const ITEM_LOCAL: &str = "# Profile Template for Clash Verge

proxies: []

proxy-groups: []

rules: []
";

/// enhanced profile
pub const ITEM_MERGE: &str = "# Profile Enhancement Merge Template for Clash Verge

profile:
  store-selected: true
";

pub const ITEM_MERGE_EMPTY: &str = "# Profile Enhancement Merge Template for Clash Verge

";

/// enhanced profile
pub const ITEM_SCRIPT: &str = "// Define main function (script entry)

function main(config, profileName) {
  return config;
}
";

/// enhanced profile
pub const ITEM_RULES: &str = r#"# Profile Enhancement Rules Template for Clash Verge
#
# Split routing: send some sites/apps DIRECT and others through the proxy.
# These rules are merged into whichever profile is active, so they survive
# subscription updates and profile switches.
#
#   prepend -> inserted ABOVE the profile's own rules (checked FIRST).
#              Put your exceptions here. This is the one you usually want.
#   append  -> added BELOW them (checked last).
#   delete  -> removes a rule from the profile by exact string match.
#
# Format:  TYPE,VALUE,TARGET
#   TARGET = DIRECT  -> bypass the proxy (traffic goes out normally)
#            REJECT  -> block it
#            Manual  -> send through the proxy (any proxy-group name works)
#
# The FIRST matching rule wins, so order matters.
#
# ---- Route a SITE ----------------------------------------------------
#   - DOMAIN-SUFFIX,example.com,DIRECT   # example.com AND its subdomains
#   - DOMAIN,api.example.com,Manual      # that exact hostname only
#   - DOMAIN-KEYWORD,google,Manual       # any domain containing "google"
#   - GEOIP,IR,DIRECT,no-resolve         # every server located in Iran
#
# ---- Route an APP ----------------------------------------------------
# Per-app rules require TUN mode to be ON (system proxy alone can't see
# which app a connection belongs to).
#   - PROCESS-NAME,Telegram.exe,Manual   # this app goes through the proxy
#   - PROCESS-NAME,chrome.exe,DIRECT     # this app bypasses the proxy
#
# ---- Block -----------------------------------------------------------
#   - DOMAIN-SUFFIX,ads.example.com,REJECT

prepend:
  # Uncomment to send all Iranian sites straight out (no proxy):
  # - DOMAIN-SUFFIX,ir,DIRECT
  # - GEOIP,IR,DIRECT,no-resolve

  # Your own rules go here, for example:
  # - DOMAIN-SUFFIX,bank.ir,DIRECT
  # - PROCESS-NAME,Telegram.exe,Manual

append: []

delete: []
"#;

/// enhanced profile
pub const ITEM_PROXIES: &str = "# Profile Enhancement Proxies Template for Clash Verge

prepend: []

append: []

delete: []
";

/// enhanced profile
pub const ITEM_GROUPS: &str = "# Profile Enhancement Groups Template for Clash Verge

prepend: []

append: []

delete: []
";
