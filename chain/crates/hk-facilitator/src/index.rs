//! Dependency-free keyword index over a directory of text/markdown files.
//! Deliberately simple (TF scoring + snippet) — this is the search a paid agent
//! actually receives. `agentic/turbovec` (quantized SIMD vector search) is the
//! drop-in upgrade: same `search(query, k) -> Vec<Hit>` shape, better relevance.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Hit {
    pub path: String,
    pub score: u32,
    pub snippet: String,
}

pub struct Index {
    docs: Vec<Doc>,
}

struct Doc {
    path: String,
    text: String,
    lower: String,
    tf: HashMap<String, u32>,
}

fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_string())
        .collect()
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // skip vendored / build dirs to keep the corpus tight
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | "node_modules" | ".git" | "vendor" | ".next") {
                    continue;
                }
                collect_files(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("md") {
                out.push(p);
            }
        }
    }
}

impl Index {
    pub fn build(root: &Path) -> Self {
        let mut files = Vec::new();
        collect_files(root, &mut files);
        let mut docs = Vec::new();
        for f in files {
            if let Ok(text) = fs::read_to_string(&f) {
                let mut tf: HashMap<String, u32> = HashMap::new();
                for tok in tokenize(&text) {
                    *tf.entry(tok).or_insert(0) += 1;
                }
                docs.push(Doc {
                    path: f.to_string_lossy().to_string(),
                    lower: text.to_lowercase(),
                    text,
                    tf,
                });
            }
        }
        Self { docs }
    }

    pub fn doc_count(&self) -> usize {
        self.docs.len()
    }

    pub fn search(&self, query: &str, k: usize) -> Vec<Hit> {
        let terms = tokenize(query);
        let mut scored: Vec<Hit> = Vec::new();
        for d in &self.docs {
            let mut score = 0u32;
            for t in &terms {
                score += d.tf.get(t).copied().unwrap_or(0);
            }
            if score > 0 {
                scored.push(Hit { path: d.path.clone(), score, snippet: d.snippet(&terms) });
            }
        }
        scored.sort_by(|a, b| b.score.cmp(&a.score));
        scored.truncate(k);
        scored
    }
}

impl Doc {
    fn snippet(&self, terms: &[String]) -> String {
        // Find the first occurrence of any query term; return ~180 chars around it.
        let pos = terms
            .iter()
            .filter_map(|t| self.lower.find(t.as_str()))
            .min()
            .unwrap_or(0);
        let start = pos.saturating_sub(60);
        let end = (pos + 120).min(self.text.len());
        let raw = &self.text[clamp_char_boundary(&self.text, start)..clamp_char_boundary(&self.text, end)];
        raw.replace('\n', " ").trim().to_string()
    }
}

fn clamp_char_boundary(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        i = s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
