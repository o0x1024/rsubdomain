use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead};

use crate::subdata;

pub(super) fn resolve_dictionary(
    dictionary: Option<&Vec<String>>,
    dictionary_file: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if let Some(dictionary) = dictionary {
        return Ok(normalize_dictionary_entries(dictionary.iter().cloned()));
    }

    if let Some(file_path) = dictionary_file {
        return load_dictionary_from_file(file_path);
    }

    Ok(subdata::get_default_sub_next_data()
        .iter()
        .map(|value| (*value).to_string())
        .collect())
}

pub(super) fn load_dictionary_from_file(
    file_path: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader.lines().collect::<Result<Vec<_>, _>>()?;
    Ok(normalize_dictionary_entries(lines))
}

pub(super) fn normalize_dictionary_entries<I>(entries: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for entry in entries {
        let value = entry.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }

        let value = value.trim_matches('.');
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            continue;
        }

        let value = value.to_string();
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::{normalize_dictionary_entries, resolve_dictionary};

    #[test]
    fn normalize_dictionary_entries_skips_blank_comments_and_duplicates() {
        let entries = vec![
            "".to_string(),
            "  ".to_string(),
            "# comment".to_string(),
            "www".to_string(),
            ".mail.".to_string(),
            "www".to_string(),
            "api v2".to_string(),
            "api.v2".to_string(),
        ];

        let normalized = normalize_dictionary_entries(entries);

        assert_eq!(normalized, vec!["www", "mail", "api.v2"]);
    }

    #[test]
    fn resolve_dictionary_uses_embedded_defaults_when_no_source_is_provided() {
        let dictionary = resolve_dictionary(None, None).expect("embedded dictionary should load");

        assert!(!dictionary.is_empty());
        assert_eq!(dictionary[0], "vk");
    }
}
