// dns_lookup.rs — Rust версия

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::time::Instant;
use std::sync::Arc;
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DNSResult {
    domain: String,
    timestamp: String,
    AAAA: Vec<String>,
    PTR: Vec<String>,
}

impl DNSResult {
    fn new(domain: String) -> Self {
        DNSResult {
            domain,
            timestamp: chrono::Utc::now().to_rfc3339(),
            AAAA: Vec::new(),
            PTR: Vec::new(),
        }
    }
}

fn is_ipv6(addr: &str) -> bool {
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

async fn lookup_domain(domain: &str) -> Option<DNSResult> {
    let domain = domain.trim();
    if domain.is_empty() {
        return None;
    }

    let mut result = DNSResult::new(domain.to_string());

    // Проверяем, является ли строка IPv6-адресом
    if is_ipv6(domain) {
        if let Ok(ips) = tokio::net::lookup_host((domain, 0)).await {
            for ip in ips {
                if ip.is_ipv6() {
                    if let Ok(ptr) = tokio::net::lookup_host((ip.ip().to_string(), 0)).await {
                        for p in ptr {
                            result.PTR.push(p.ip().to_string());
                        }
                    }
                }
            }
        }
        if result.PTR.is_empty() {
            result.PTR.push("не найден".to_string());
        }
        return Some(result);
    }

    // AAAA lookup
    if let Ok(ips) = tokio::net::lookup_host((domain, 0)).await {
        for ip in ips {
            if ip.is_ipv6() {
                result.AAAA.push(ip.ip().to_string());
            }
        }
    }

    // PTR для каждого AAAA адреса
    if !result.AAAA.is_empty() {
        for ip in &result.AAAA {
            if let Ok(ips) = tokio::net::lookup_host((ip.as_str(), 0)).await {
                for p in ips {
                    result.PTR.push(p.ip().to_string());
                }
            }
        }
    }
    if result.PTR.is_empty() {
        result.PTR.push("не найден".to_string());
    }

    Some(result)
}

async fn lookup_batch(domains: Vec<String>, threads: usize) -> Vec<DNSResult> {
    println!("🔍 Выполняем lookup для {} доменов...", domains.len());
    let start = Instant::now();

    let semaphore = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();

    for domain in domains {
        if domain.trim().is_empty() {
            continue;
        }
        let sem = semaphore.clone();
        let domain = domain.trim().to_string();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = lookup_domain(&domain).await;
            if let Some(r) = result {
                println!("✅ {} — выполнено", domain);
                r
            } else {
                println!("⚠️ {} — ошибка", domain);
                DNSResult::new(domain)
            }
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            if !result.AAAA.is_empty() || result.PTR.iter().any(|p| p != "не найден") {
                results.push(result);
            }
        }
    }

    println!("⏱️ Время выполнения: {:.2} сек.", start.elapsed().as_secs_f64());
    results
}

fn print_table(results: &[DNSResult]) {
    if results.is_empty() {
        println!("Нет результатов.");
        return;
    }

    println!("\n{}", "=".repeat(90));
    println!("{:<25} {:<35} {:<25}", "Домен/IP", "AAAA", "PTR");
    println!("{}", "-".repeat(90));
    for r in results {
        let aaaa = r.AAAA.join("; ");
        let aaaa = if aaaa.is_empty() { "—".to_string() } else { aaaa };
        let aaaa = if aaaa.len() > 35 { &aaaa[..35] } else { &aaaa };
        let ptr = r.PTR.join("; ");
        let ptr = if ptr.len() > 25 { &ptr[..25] } else { &ptr };
        println!("{:<25} {:<35} {:<25}", r.domain, aaaa, ptr);
    }
    println!("{}", "=".repeat(90));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run -- <domains.txt>");
        println!("   или: cargo run -- domain1.com domain2.com");
        return Ok(());
    }

    let mut domains = Vec::new();

    if args.len() == 2 && std::path::Path::new(&args[1]).exists() {
        let file = File::open(&args[1])?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let domain = line.trim();
            if !domain.is_empty() {
                domains.push(domain.to_string());
            }
        }
    } else {
        for arg in args.iter().skip(1) {
            if !arg.is_empty() {
                domains.push(arg.clone());
            }
        }
    }

    if domains.is_empty() {
        println!("❌ Нет доменов для проверки.");
        return Ok(());
    }

    println!("🌐 DNS Lookup IPv6 Pro (Rust)");
    println!("📂 Загружено {} доменов.", domains.len());

    let results = lookup_batch(domains, 20).await;

    if !results.is_empty() {
        print_table(&results);

        let json = serde_json::to_string_pretty(&results)?;
        let mut file = File::create("dns_results.json")?;
        file.write_all(json.as_bytes())?;
        println!("💾 Сохранено JSON: dns_results.json");

        let mut csv_file = File::create("dns_results.csv")?;
        writeln!(csv_file, "Domain,Timestamp,AAAA,PTR")?;
        for r in &results {
            writeln!(csv_file, "{},{},{},{}",
                r.domain, r.timestamp,
                r.AAAA.join("; "),
                r.PTR.join("; ")
            )?;
        }
        println!("💾 Сохранено CSV: dns_results.csv");
    } else {
        println!("❌ Не удалось выполнить lookup.");
    }

    Ok(())
}
