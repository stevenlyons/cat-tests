//! Cross-check out/tokens.json with fastly/rust-cat.
//!
//! For every token: decode with `Token::from_bytes`, verify the HMAC with `Token::verify`,
//! and export what rust-cat's typed API reads (registered + custom claims) so
//! tools/validate.py can compare it with the manifest.
//!
//! For catm / catreplay / catnetprint (key 324) it also records rust-cat's own
//! `verify_claims` verdict. Those verdicts are informational: expected results come from the
//! spec (rust-cat is known to compare catm case-insensitively).
//!
//! Usage (from rust-check/):
//!     cargo run --release -- [../out/tokens.json] [../keys/hs256-test-key.json] [../out/rustcat.json]

use std::env;
use std::fs;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common_access_token::{CborValue, FingerprintType, Token, VerificationOptions};
use serde_json::{json, Map as JsonMap, Value};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex in key file"))
        .collect()
}

/// Same typed-JSON shape as catcheck/cbor.py::to_typed_json.
#[allow(unreachable_patterns)]
fn typed(v: &CborValue) -> Value {
    match v {
        CborValue::Integer(i) => {
            json!({"type": if *i >= 0 { "uint" } else { "nint" }, "value": i})
        }
        CborValue::Bytes(b) => json!({"type": "bstr", "hex": to_hex(b)}),
        CborValue::Text(s) => json!({"type": "tstr", "value": s}),
        CborValue::Array(a) => json!({"type": "array", "items": a.iter().map(typed).collect::<Vec<_>>()}),
        CborValue::Map(m) => json!({
            "type": "map",
            "entries": m
                .iter()
                .map(|(k, v)| json!({"key": typed(&CborValue::Integer(*k as i64)), "value": typed(v)}))
                .collect::<Vec<_>>()
        }),
        CborValue::Null => json!({"type": "null"}),
        _ => json!({"type": "unsupported-by-rust-check"}),
    }
}

fn verdict(r: Result<(), common_access_token::Error>) -> Value {
    match r {
        Ok(()) => json!("ok"),
        Err(e) => json!(format!("error: {e}")),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let tokens_path = args.get(1).map(String::as_str).unwrap_or("../out/tokens.json");
    let key_path = args.get(2).map(String::as_str).unwrap_or("../keys/hs256-test-key.json");
    let out_path = args.get(3).map(String::as_str).unwrap_or("../out/rustcat.json");

    let key_doc: Value = serde_json::from_str(&fs::read_to_string(key_path).expect("read key file"))
        .expect("parse key file");
    let key = from_hex(key_doc["key_hex"].as_str().expect("key_hex"));

    let doc: Value = serde_json::from_str(&fs::read_to_string(tokens_path).expect("read tokens"))
        .expect("parse tokens");
    let tokens = doc["tokens"].as_array().expect("tokens array");

    let mut results = Vec::new();
    for t in tokens {
        let id = t["id"].as_str().unwrap_or("?");
        let claim_key = t["claim_key"].as_i64().unwrap_or(0);
        let req = &t["request"];
        let bytes = match URL_SAFE_NO_PAD.decode(t["token_b64url"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => {
                results.push(json!({"id": id, "decode_ok": false, "error": format!("base64: {e}")}));
                continue;
            }
        };
        let token = match Token::from_bytes(&bytes) {
            Ok(tok) => tok,
            Err(e) => {
                results.push(json!({"id": id, "decode_ok": false, "error": format!("{e}")}));
                continue;
            }
        };
        let mac_ok = token.verify(&key).is_ok();
        let wrong_key_rejected = token.verify(&[0u8; 32]).is_err();

        let r = &token.claims.registered;
        let mut reg = JsonMap::new();
        if let Some(v) = &r.iss { reg.insert("iss".into(), json!(v)); }
        if let Some(v) = &r.sub { reg.insert("sub".into(), json!(v)); }
        if let Some(v) = &r.aud { reg.insert("aud".into(), json!(v)); }
        if let Some(v) = r.exp { reg.insert("exp".into(), json!(v)); }
        if let Some(v) = r.nbf { reg.insert("nbf".into(), json!(v)); }
        if let Some(v) = r.iat { reg.insert("iat".into(), json!(v)); }
        if let Some(v) = &r.cti { reg.insert("cti".into(), json!(to_hex(v))); }

        let mut custom = JsonMap::new();
        for (k, v) in &token.claims.custom {
            custom.insert(k.to_string(), typed(v));
        }

        // rust-cat's own claim verdicts (informational)
        let base = VerificationOptions::new().verify_exp(false).verify_nbf(false);
        let rc_verdict = match claim_key {
            313 => {
                let m = req["method"].as_str().unwrap_or("GET");
                verdict(token.verify_claims(&base.verify_catm(true).http_method(m)))
            }
            308 => {
                let seen = req["cti_seen_before"].as_bool().unwrap_or(false);
                verdict(token.verify_claims(&base.verify_catreplay(true).token_seen_before(seen)))
            }
            324 => {
                let fp = &req["tls"]["fingerprint"];
                let mut opts = base.verify_cattprint(true);
                if let (Some(ty), Some(val)) = (fp["type"].as_i64(), fp["value"].as_str()) {
                    match FingerprintType::from_i64(ty) {
                        Some(ft) => opts = opts.fingerprint_type(ft).fingerprint_value(val),
                        None => {}
                    }
                }
                verdict(token.verify_claims(&opts))
            }
            _ => Value::Null,
        };

        results.push(json!({
            "id": id,
            "decode_ok": true,
            "mac_ok": mac_ok && wrong_key_rejected,
            "registered": Value::Object(reg),
            "custom": Value::Object(custom),
            "rustcat_verify_claims": rc_verdict,
        }));
    }

    let out = json!({
        "_comment": "Generated by rust-check (fastly/rust-cat cross-check). Do not edit by hand.",
        "results": results,
    });
    fs::write(out_path, serde_json::to_string_pretty(&out).expect("serialize")).expect("write output");
    println!("rust-check: {} tokens checked -> {}", tokens.len(), out_path);
}
