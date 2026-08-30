use std::collections::HashMap;

/// Shannon entropy of a multiset of string labels (e.g. source IPs).
/// Higher entropy => more diverse / more likely spoofed or distributed.
pub fn shannon_entropy(labels: &[&str]) -> f64 {
    if labels.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for l in labels {
        *counts.entry(*l).or_insert(0) += 1;
    }
    let total = labels.len() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Shannon entropy of the characters in a single string (e.g. a DNS query).
pub fn string_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let total = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of the subdomain portion of a domain (labels before the last two).
pub fn subdomain_entropy(domain: &str) -> f64 {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return 0.0;
    }
    let sub = labels[..labels.len() - 2].join(".");
    string_entropy(&sub)
}
