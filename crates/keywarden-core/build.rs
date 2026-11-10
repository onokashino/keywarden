//! Встраивает каталоги переводов: каждая папка `locales/<код>/` с файлами `*.json` становится
//! языком интерфейса. Новый язык: создать папку (см. docs/translating.md), код не трогать.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../locales");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut langs: Vec<PathBuf> = std::fs::read_dir(&root)
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    langs.sort();
    let mut out = String::from(
        "/// (код языка, название на нём самом, содержимое файлов каталога)\n\
         pub(crate) const CATALOGS: &[(&str, &str, &[&str])] = &[\n",
    );
    for dir in langs {
        println!("cargo:rerun-if-changed={}", dir.display());
        let code = dir.file_name().unwrap().to_string_lossy().into_owned();
        let name = native_name(&dir).unwrap_or_else(|| code.clone());
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "json")
                    && p.file_name().is_some_and(|n| n != "_meta.json")
            })
            .collect();
        files.sort();
        write!(out, "    ({code:?}, {name:?}, &[").unwrap();
        for f in files {
            println!("cargo:rerun-if-changed={}", f.display());
            let abs = f.canonicalize().unwrap();
            write!(out, "include_str!({:?}), ", abs.display().to_string()).unwrap();
        }
        out.push_str("]),\n");
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("catalogs.rs");
    std::fs::write(dest, out).unwrap();
}

/// `_meta.json`: {"name": "Deutsch"}; без JSON-библиотеки, формат простой.
fn native_name(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("_meta.json")).ok()?;
    let after = text.split("\"name\"").nth(1)?;
    let value = after.split('"').nth(1)?;
    Some(value.to_string())
}
