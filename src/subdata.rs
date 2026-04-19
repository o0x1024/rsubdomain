use std::sync::OnceLock;

static DEFAULT_SUBDOMAINS: OnceLock<Vec<&'static str>> = OnceLock::new();

pub fn get_default_sub_next_data() -> &'static [&'static str] {
    DEFAULT_SUBDOMAINS
        .get_or_init(|| {
            include_str!("../data/default_subdomains.txt")
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect()
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::get_default_sub_next_data;

    #[test]
    fn loads_default_subdomains_from_embedded_data_file() {
        let subdomains = get_default_sub_next_data();

        assert!(!subdomains.is_empty());
        assert_eq!(subdomains[0], "vk");
        assert!(subdomains.contains(&"sbs"));
        assert!(!subdomains.iter().any(|value| value.is_empty()));
    }
}
