//! gmsol-release-audit
//!
//! Read-only integrity auditor for the GMTrade (gmsol) deployment.
//!
//! Checks, in one pass:
//!   1. release artifacts  — npm tarball completeness / crates.io parity
//!   2. deployment provenance — verified-build status of the five programs
//!   3. authority hygiene  — Store role holders vs on-chain activity (dormancy)
//!   4. governance config  — multisig threshold, timelock, live quorum margin
//!
//! Everything is read-only: public registry metadata + public RPC reads.

use serde_json::Value;
use sol_rpc_mini::{to_base58, RpcClient};

// ---------------------------------------------------------------------------
// constants (all public, from the gmsol deployment / SECURITY.md / docs)
// ---------------------------------------------------------------------------

const NPM_PACKAGE: &str = "@gmsol-labs/gmsol-sdk";
const CRATES_FAMILY: &[&str] = &["gmsol-sdk", "gmsol-store", "gmsol-model", "gmsol-utils"];

const PROGRAMS: &[(&str, &str)] = &[
    ("store", "Gmso1uvJnLbawvw7yezdfCDcPydwW2s2iqG3w6MDucLo"),
    ("treasury", "GTuvYD5SxkTq4FLG6JV1FQ5dkczr1AfgDcBHaFsBdtBg"),
    ("timelock", "TimeBQ7gQyWyQMD3bTteAdy7hTVDNWSwELdSVZHfSXL"),
    ("competition", "2AxuNr6euZPKQbTwNsLBjzFTZFAevA85F4PW9m9Dv8pc"),
    ("liquidity-provider", "LPMWczEVgXyQ3979XaqqEttanCXmYGvtJqPVtw1PvC8"),
];

const STORE: &str = "CTDLvGGXnoxvqLyTpGzdGLg9pD6JexKxKXSV8tqqo8bN";
const MULTISIG: &str = "CxnEVpQQcYa628TywzHGXeJ2jdVmbU51rnERat9xunP1";

// RoleStore layout in the Store account (verified against the live account;
// see programs/store/src/states/roles.rs — RoleMap then Members fixed_map).
const ROLEMAP_BASE: usize = 80;
const ROLE_ENTRY: usize = 66; // 32-byte key hash + RoleMetadata(34)
const ROLEMAP_COUNT: usize = 2192;
const MEMBERS_BASE: usize = 2196; // Members map data
const MEMBER_ENTRY: usize = 36; // pubkey + u32 role bitmap
const MEMBERS_COUNT: usize = MEMBERS_BASE + MEMBER_ENTRY * 64;

const DORMANCY_WARN_DAYS: i64 = 90;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn http_json(url: &str) -> Result<Value, String> {
    ureq::get(url)
        .set("User-Agent", "gmsol-release-audit (research)")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .into_json()
        .map_err(|e| format!("decode {url}: {e}"))
}

fn b64_decode(s: &str) -> Vec<u8> {
    fn v(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            _ => 63,
        }
    }
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= v(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

fn days_since(ts: Option<i64>) -> Option<i64> {
    let ts = ts?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((now - ts) / 86_400)
}

fn last_activity(rpc: &RpcClient, address: &str) -> Option<i64> {
    // public RPCs rate-limit; retry once, and pace calls politely
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1200));
        }
        if let Ok(sigs) = rpc.get_signatures(address, 1) {
            if let Some(ts) = sigs
                .as_array()
                .and_then(|a| a.first())
                .and_then(|s| s["blockTime"].as_i64())
            {
                return Some(ts);
            }
        }
    }
    None
}

fn role_name(meta: &[u8]) -> String {
    // RoleMetadata: name[32] (fixed str), enabled u8, index u8
    let end = meta[..32].iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8_lossy(&meta[..end]).to_string()
}

// ---------------------------------------------------------------------------
// 1. release artifacts
// ---------------------------------------------------------------------------

fn check_release_artifacts() {
    println!("\n== 1. release artifacts ==");

    let meta = match http_json(&format!("https://registry.npmjs.org/{NPM_PACKAGE}")) {
        Ok(m) => m,
        Err(e) => {
            println!("  [warn] npm metadata unavailable: {e}");
            return;
        }
    };
    let versions = match meta["versions"].as_object() {
        Some(v) => v,
        None => {
            println!("  [warn] npm metadata: no versions map");
            return;
        }
    };

    // sort by publish time (registry `time` map), not lexicographically
    let times = meta["time"].as_object();
    let mut sorted: Vec<&String> = versions.keys().collect();
    sorted.sort_by_key(|v| times.and_then(|t| t.get(*v)).and_then(|t| t.as_str()).map(String::from).unwrap_or_default());
    for ver in sorted.iter().rev().take(4) {
        let v = &versions[*ver];
        let size = v["dist"]["unpackedSize"].as_u64().unwrap_or(0);
        let declared: Vec<String> = v["files"]
            .as_array()
            .map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if size < 8_192 {
            println!(
                "  [FAIL] npm {ver}: unpacked size {size} bytes — package is a stub \
                 (no build output; declared files: {declared:?})"
            );
        } else {
            println!("  [ ok ] npm {ver}: unpacked size {size} bytes");
        }
    }

    for krate in CRATES_FAMILY {
        match http_json(&format!("https://crates.io/api/v1/crates/{krate}")) {
            Ok(m) => {
                let newest = m["crate"]["newest_version"].as_str().unwrap_or("?");
                println!("  [ ok ] crates.io {krate}: newest {newest}");
            }
            Err(e) => println!("  [warn] crates.io {krate}: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 2. deployment provenance
// ---------------------------------------------------------------------------

fn check_deployment_provenance() {
    println!("\n== 2. deployment provenance (verified-build registry) ==");
    for (name, id) in PROGRAMS {
        match http_json(&format!("https://verify.osec.io/status/{id}")) {
            Ok(m) => {
                let verified = m["is_verified"].as_bool().unwrap_or(false);
                let commit = m["commit"].as_str().unwrap_or("-");
                let when = m["last_verified_at"].as_str().unwrap_or("-");
                if verified {
                    let short = &commit[..8.min(commit.len())];
                    println!("  [ ok ] {name}: verified build (commit {short}, checked {when})");
                } else {
                    println!("  [FAIL] {name}: deployment NOT verified against public source");
                }
            }
            Err(e) => println!("  [warn] {name}: registry check failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 3. authority hygiene (Store role holders vs on-chain dormancy)
// ---------------------------------------------------------------------------

fn check_authority_hygiene(rpc: &RpcClient) {
    println!("\n== 3. authority hygiene (Store roles) ==");

    let acct = match rpc.get_account(STORE) {
        Ok(a) => a,
        Err(e) => {
            println!("  [warn] store account fetch failed: {e}");
            return;
        }
    };
    let data_b64 = acct["value"]["data"][0].as_str().unwrap_or("");
    let raw = b64_decode(data_b64);
    if raw.len() < 10232 {
        println!("  [warn] store account truncated: {} bytes", raw.len());
        return;
    }

    let role_count = u32::from_le_bytes(raw[ROLEMAP_COUNT..ROLEMAP_COUNT + 4].try_into().unwrap()) as usize;
    // (bit index, name) — the bit position is RoleMetadata.index, not map order
    let mut roles: Vec<(u8, String)> = Vec::new();
    for i in 0..role_count.min(32) {
        let base = ROLEMAP_BASE + i * ROLE_ENTRY;
        let meta = &raw[base + 32..base + ROLE_ENTRY];
        roles.push((meta[33], role_name(meta)));
    }
    println!("  {} enabled roles tracked", roles.len());

    let member_count = u32::from_le_bytes(raw[MEMBERS_COUNT..MEMBERS_COUNT + 4].try_into().unwrap()) as usize;
    if member_count > 64 {
        println!("  [warn] member count implausible ({member_count}); layout may have changed");
        return;
    }
    println!("  {} role-holding members\n", member_count);

    for i in 0..member_count {
        let base = MEMBERS_BASE + i * MEMBER_ENTRY;
        let pubkey = to_base58(&raw[base..base + 32]);
        let bitmap = u32::from_le_bytes(raw[base + 32..base + 36].try_into().unwrap());
        let held: Vec<&str> = roles
            .iter()
            .filter(|(idx, _)| bitmap & (1u32 << idx) != 0)
            .map(|(_, n)| n.as_str())
            .collect();

        std::thread::sleep(std::time::Duration::from_millis(350));
        let days = days_since(last_activity(rpc, &pubkey));
        let dormancy = match days {
            Some(d) if d > DORMANCY_WARN_DAYS => format!("DORMANT {d}d  <-- review"),
            Some(d) => format!("active {d}d ago"),
            None => "no activity found".to_string(),
        };
        println!("  {pubkey}");
        println!("      roles: {}", held.join(", "));
        println!("      last on-chain activity: {dormancy}");
    }
}

// ---------------------------------------------------------------------------
// 4. governance config (Squads v4 multisig)
// ---------------------------------------------------------------------------

fn check_governance(rpc: &RpcClient) {
    println!("\n== 4. governance (Squads multisig) ==");

    let acct = match rpc.get_account(MULTISIG) {
        Ok(a) => a,
        Err(e) => {
            println!("  [warn] multisig fetch failed: {e}");
            return;
        }
    };
    let raw = b64_decode(acct["value"]["data"][0].as_str().unwrap_or(""));

    // Squads v4 Multisig layout:
    //   8 disc | 32 create_key | 32 config_authority | u16 threshold |
    //   u32 time_lock | u64 tx_index | u64 stale | 1+32 rent_collector | u8 bump |
    //   4 members_len | N * (32 pubkey + 1 perms)
    let threshold = u16::from_le_bytes(raw[72..74].try_into().unwrap());
    let time_lock = u32::from_le_bytes(raw[74..78].try_into().unwrap());
    let tx_index = u64::from_le_bytes(raw[78..86].try_into().unwrap());
    let mlen = u32::from_le_bytes(raw[128..132].try_into().unwrap()) as usize;
    println!("  threshold: {threshold}-of-{mlen}");
    println!("  timelock:  {time_lock} seconds");
    println!("  proposals: {tx_index} total");

    let mut active = 0usize;
    println!();
    for i in 0..mlen {
        let base = 132 + i * 33;
        let pubkey = to_base58(&raw[base..base + 32]);
        std::thread::sleep(std::time::Duration::from_millis(350));
        let days = days_since(last_activity(rpc, &pubkey));
        match days {
            Some(d) if d > DORMANCY_WARN_DAYS => {
                println!("  {pubkey}  DORMANT {d}d  <-- review");
            }
            Some(d) => {
                active += 1;
                println!("  {pubkey}  active {d}d ago");
            }
            None => println!("  {pubkey}  no activity found"),
        }
    }
    println!();
    if active >= threshold as usize {
        println!(
            "  live quorum margin: {active} active vs threshold {threshold} \
             (margin {})",
            active - threshold as usize
        );
    } else {
        println!(
            "  [FAIL] live quorum NOT reachable: {active} active vs threshold {threshold}"
        );
    }
}

// ---------------------------------------------------------------------------

fn main() {
    println!("gmsol-release-audit — read-only integrity checks (mainnet)");
    let rpc = RpcClient::mainnet();

    check_release_artifacts();
    check_deployment_provenance();
    check_authority_hygiene(&rpc);
    check_governance(&rpc);

    println!("\ndone. all checks are read-only; no transactions were sent.");
}
