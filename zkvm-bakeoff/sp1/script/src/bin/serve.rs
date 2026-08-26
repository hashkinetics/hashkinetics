//! hk-prove — the SP1-CUDA proving service (P2.0/WS2).
//!
//! Runs in WSL next to the GPU. Wallets/demos POST a witness; they get back a real STARK
//! proof (hex bincode of `SP1ProofWithPublicValues`) that any hk-node with the matching
//! verifying key accepts. Every proof is self-verified here before it is returned.
//!
//! Protocol: POST any path, JSON body {"method": ..., "params": {...}}:
//!   health                          -> {ok, mode}
//!   vks                             -> {spend_vk, mint_vk}          (hex bincode SP1VerifyingKey)
//!   prove_spend {witness}           -> {proof, public, prove_ms}    (witness = SpendWitness JSON)
//!   prove_mint  {witness}           -> {proof, public, prove_ms}    (witness = MintWitness JSON)
//!
//! Env: HK_PROVE_ADDR (default 0.0.0.0:9911 — reachable from Windows via localhost),
//!      HK_PROVE_MODE=core|compressed (default core: 1.24 s measured; compressed ~2 s,
//!      the recursion-ready artifact — both verify with the same vk API).
//!
//! Requests are handled SEQUENTIALLY (one GPU, serial proving — queueing is the mempool's
//! job, not ours). Devnet-grade service; the production `hk-prove` gets auth + queues (WS2+).

use std::time::Instant;

use hk_spend_circuit::agg::{agg_digest, agg_leaf, KIND_MINT, KIND_SPEND};
use hk_spend_circuit::{run, run_mint, MintWitness, SpendWitness};
use serde_json::{json, Value};
use sp1_sdk::prelude::*;
use sp1_sdk::{ProverClient, SP1Proof, SP1ProofWithPublicValues};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SPEND_ELF: Elf = include_elf!("hk-spend-program");
const MINT_ELF: Elf = include_elf!("hk-mint-program");
const AGG_ELF: Elf = include_elf!("hk-agg-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let addr = std::env::var("HK_PROVE_ADDR").unwrap_or_else(|_| "0.0.0.0:9911".into());
    let core_mode = std::env::var("HK_PROVE_MODE").map(|v| v != "compressed").unwrap_or(true);
    let mode = if core_mode { "core" } else { "compressed" };

    println!("hk-prove: building CUDA prover client...");
    let client = ProverClient::builder().cuda().build().await;

    println!("hk-prove: setup (spend + mint + aggregation programs)...");
    let spend_pk = client.setup(SPEND_ELF).await.expect("spend setup failed");
    let mint_pk = client.setup(MINT_ELF).await.expect("mint setup failed");
    let agg_pk = client.setup(AGG_ELF).await.expect("agg setup failed");
    let spend_vk_hex =
        hex::encode(bincode::serialize(spend_pk.verifying_key()).expect("vk serialize"));
    let mint_vk_hex =
        hex::encode(bincode::serialize(mint_pk.verifying_key()).expect("vk serialize"));
    let agg_vk_hex = hex::encode(bincode::serialize(agg_pk.verifying_key()).expect("vk serialize"));

    // Warm-up prove (GPU kernel init) so the first real request sees steady-state latency.
    println!("hk-prove: warm-up prove ({mode})...");
    {
        let mut stdin = SP1Stdin::new();
        stdin.write(&hk_spend_circuit::build_valid_spend(7));
        let t = Instant::now();
        let p = if core_mode {
            client.prove(&spend_pk, stdin).core().await.expect("warm-up prove failed")
        } else {
            client.prove(&spend_pk, stdin).compressed().await.expect("warm-up prove failed")
        };
        client.verify(&p, spend_pk.verifying_key(), None).expect("warm-up verify failed");
        println!(
            "hk-prove: warm-up ok in {} ms (incl. first-touch overhead)",
            t.elapsed().as_millis()
        );
    }

    let listener = TcpListener::bind(&addr).await.expect("bind failed");
    println!("hk-prove: listening on {addr}  mode={mode}");
    println!(
        "hk-prove: spend_vk[0..16]={}  mint_vk[0..16]={}",
        &spend_vk_hex[..16],
        &mint_vk_hex[..16]
    );
    println!("hk-prove: point the devnet at me:  .\\devnet.ps1 -Fresh -ProverUrl http://127.0.0.1:9911");

    // Sequential accept loop on purpose: one GPU, serial proving.
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        let req = match read_request(&mut sock).await {
            Ok(Some(req)) => req,
            Ok(None) => continue,
            Err(e) => {
                let _ = respond(&mut sock, 400, &json!({"error": format!("bad request: {e}")})).await;
                continue;
            }
        };
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        // Dispatch inline so every SDK type stays inferred (same shapes as bin/cuda.rs).
        let resp: Value = match method {
            "health" => json!({"result": {"ok": true, "mode": mode}}),
            "vks" => json!({"result": {"spend_vk": &spend_vk_hex, "mint_vk": &mint_vk_hex, "agg_vk": &agg_vk_hex}}),
            "prove_spend" => {
                match serde_json::from_value::<SpendWitness>(
                    params.get("witness").cloned().unwrap_or(Value::Null),
                ) {
                    Err(e) => json!({"error": format!("bad witness: {e}")}),
                    // Native pre-check: refuse to burn GPU time on an unprovable witness.
                    Ok(w) => match run(&w) {
                        Err(e) => json!({"error": format!("witness fails the statement: {e:?}")}),
                        Ok(public) => {
                            // Per-request mode override (aggregation needs compressed).
                            let req_core = params
                                .get("mode")
                                .and_then(|m| m.as_str())
                                .map(|m| m != "compressed")
                                .unwrap_or(core_mode);
                            let mut stdin = SP1Stdin::new();
                            stdin.write(&w);
                            let t = Instant::now();
                            let proved = if req_core {
                                client.prove(&spend_pk, stdin).core().await
                            } else {
                                client.prove(&spend_pk, stdin).compressed().await
                            };
                            match proved {
                                Err(e) => json!({"error": format!("proving failed: {e}")}),
                                Ok(proof) => {
                                    let prove_ms = t.elapsed().as_millis() as u64;
                                    if let Err(e) =
                                        client.verify(&proof, spend_pk.verifying_key(), None)
                                    {
                                        json!({"error": format!("self-verify failed (bug!): {e}")})
                                    } else {
                                        match bincode::serialize(&proof) {
                                            Err(e) => json!({"error": format!("proof serialize: {e}")}),
                                            Ok(bytes) => {
                                                println!(
                                                    "proved SPEND in {prove_ms} ms  ({} KB)",
                                                    bytes.len() / 1024
                                                );
                                                json!({"result": {
                                                    "proof": hex::encode(bytes),
                                                    "public": serde_json::to_value(&public).unwrap(),
                                                    "prove_ms": prove_ms,
                                                }})
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
            "prove_mint" => {
                match serde_json::from_value::<MintWitness>(
                    params.get("witness").cloned().unwrap_or(Value::Null),
                ) {
                    Err(e) => json!({"error": format!("bad witness: {e}")}),
                    Ok(w) => {
                        let public = run_mint(&w);
                        let req_core = params
                            .get("mode")
                            .and_then(|m| m.as_str())
                            .map(|m| m != "compressed")
                            .unwrap_or(core_mode);
                        let mut stdin = SP1Stdin::new();
                        stdin.write(&w);
                        let t = Instant::now();
                        let proved = if req_core {
                            client.prove(&mint_pk, stdin).core().await
                        } else {
                            client.prove(&mint_pk, stdin).compressed().await
                        };
                        match proved {
                            Err(e) => json!({"error": format!("proving failed: {e}")}),
                            Ok(proof) => {
                                let prove_ms = t.elapsed().as_millis() as u64;
                                if let Err(e) = client.verify(&proof, mint_pk.verifying_key(), None)
                                {
                                    json!({"error": format!("self-verify failed (bug!): {e}")})
                                } else {
                                    match bincode::serialize(&proof) {
                                        Err(e) => json!({"error": format!("proof serialize: {e}")}),
                                        Ok(bytes) => {
                                            println!(
                                                "proved MINT in {prove_ms} ms  ({} KB)",
                                                bytes.len() / 1024
                                            );
                                            json!({"result": {
                                                "proof": hex::encode(bytes),
                                                "public": serde_json::to_value(&public).unwrap(),
                                                "prove_ms": prove_ms,
                                            }})
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "aggregate" => {
                // items: [{kind: "spend"|"mint", proof: <hex bincode SP1ProofWithPublicValues,
                // COMPRESSED mode>}] — order is preserved into the digest.
                let items = params.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
                match parse_agg_items(&items) {
                    Err(e) => json!({"error": e}),
                    Ok(parsed) if parsed.is_empty() => json!({"error": "no items"}),
                    Ok(parsed) => {
                        let kinds: Vec<u8> = parsed.iter().map(|(k, _)| *k).collect();
                        let vkeys: Vec<[u32; 8]> = parsed
                            .iter()
                            .map(|(k, _)| {
                                if *k == KIND_SPEND {
                                    spend_pk.verifying_key().hash_u32()
                                } else {
                                    mint_pk.verifying_key().hash_u32()
                                }
                            })
                            .collect();
                        let publics: Vec<Vec<u8>> =
                            parsed.iter().map(|(_, p)| p.public_values.to_vec()).collect();
                        let leaves: Vec<_> = kinds
                            .iter()
                            .zip(&vkeys)
                            .zip(&publics)
                            .map(|((k, v), pb)| agg_leaf(*k, v, pb))
                            .collect();
                        let expect_digest = agg_digest(&leaves);

                        let mut stdin = SP1Stdin::new();
                        stdin.write(&kinds);
                        stdin.write(&vkeys);
                        stdin.write(&publics);
                        let mut not_compressed = false;
                        for (k, p) in parsed {
                            match p.proof {
                                SP1Proof::Compressed(inner) => {
                                    let vkm = if k == KIND_SPEND {
                                        spend_pk.verifying_key().vk.clone()
                                    } else {
                                        mint_pk.verifying_key().vk.clone()
                                    };
                                    stdin.write_proof(*inner, vkm);
                                }
                                _ => {
                                    not_compressed = true;
                                    break;
                                }
                            }
                        }
                        if not_compressed {
                            json!({"error": "aggregation requires COMPRESSED input proofs (request prove_* with \"mode\":\"compressed\")"})
                        } else {
                            let n = kinds.len();
                            let t = Instant::now();
                            match client.prove(&agg_pk, stdin).compressed().await {
                                Err(e) => json!({"error": format!("aggregation proving failed: {e}")}),
                                Ok(proof) => {
                                    let prove_ms = t.elapsed().as_millis() as u64;
                                    if let Err(e) = client.verify(&proof, agg_pk.verifying_key(), None) {
                                        json!({"error": format!("agg self-verify failed (bug!): {e}")})
                                    } else if proof.public_values.as_slice() != expect_digest {
                                        json!({"error": "agg digest mismatch (bug!)"})
                                    } else {
                                        match bincode::serialize(&proof) {
                                            Err(e) => json!({"error": format!("agg serialize: {e}")}),
                                            Ok(bytes) => {
                                                println!(
                                                    "AGGREGATED {n} proofs in {prove_ms} ms  ({} KB)",
                                                    bytes.len() / 1024
                                                );
                                                json!({"result": {
                                                    "agg_proof": hex::encode(bytes),
                                                    "digest": hex::encode(expect_digest),
                                                    "count": n,
                                                    "prove_ms": prove_ms,
                                                }})
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            other => json!({"error": format!("unknown method: {other}")}),
        };
        let status = if resp.get("error").is_some() { 400 } else { 200 };
        let _ = respond(&mut sock, status, &resp).await;
    }
}

/// Parse aggregate items: [{kind, proof(hex)}] → (kind tag, deserialized proof).
fn parse_agg_items(items: &[Value]) -> Result<Vec<(u8, SP1ProofWithPublicValues)>, String> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let kind = match it.get("kind").and_then(|k| k.as_str()) {
            Some("spend") => KIND_SPEND,
            Some("mint") => KIND_MINT,
            _ => return Err("item.kind must be \"spend\" or \"mint\"".into()),
        };
        let hexs = it
            .get("proof")
            .and_then(|p| p.as_str())
            .ok_or_else(|| "item.proof missing".to_string())?;
        let bytes = hex::decode(hexs).map_err(|e| format!("proof hex: {e}"))?;
        let p = bincode::deserialize(&bytes).map_err(|e| format!("proof decode: {e}"))?;
        out.push((kind, p));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tiny HTTP plumbing (mirrors hk-node's rpc.rs; 16 MB body cap for fat witnesses).
// ---------------------------------------------------------------------------

async fn read_request(sock: &mut TcpStream) -> eyre::Result<Option<Value>> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 1_048_576 {
            eyre::bail!("headers too large");
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let content_len: usize = headers
        .split("\r\n")
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    if content_len > 16 * 1_048_576 {
        eyre::bail!("body too large");
    }
    while buf.len() < header_end + content_len {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[header_end..(header_end + content_len).min(buf.len())];
    Ok(Some(serde_json::from_slice(body)?))
}

async fn respond(sock: &mut TcpStream, status: u16, body: &Value) -> eyre::Result<()> {
    let payload = serde_json::to_vec(body)?;
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if status == 200 { "OK" } else { "ERR" },
        payload.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&payload).await?;
    sock.flush().await?;
    Ok(())
}
