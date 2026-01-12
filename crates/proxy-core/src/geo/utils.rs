//! Geo utility functions.

/// Convert country code to flag emoji (e.g., "CN" -> "🇨🇳").
pub fn country_to_flag(code: &str) -> String {
    if code.len() != 2 {
        return "🏳".to_string();
    }
    let chars: Vec<char> = code.to_uppercase().chars().collect();
    if chars.len() != 2 || !chars[0].is_ascii_uppercase() || !chars[1].is_ascii_uppercase() {
        return "🏳".to_string();
    }
    // Regional Indicator Symbol: U+1F1E6 ('A') to U+1F1FF ('Z')
    let a = '\u{1F1E6}' as u32;
    let c1 = char::from_u32(a + (chars[0] as u32 - 'A' as u32)).unwrap_or('?');
    let c2 = char::from_u32(a + (chars[1] as u32 - 'A' as u32)).unwrap_or('?');
    format!("{}{}", c1, c2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_to_flag() {
        assert_eq!(country_to_flag("CN"), "🇨🇳");
        assert_eq!(country_to_flag("US"), "🇺🇸");
        assert_eq!(country_to_flag("JP"), "🇯🇵");
        assert_eq!(country_to_flag(""), "🏳");
        assert_eq!(country_to_flag("X"), "🏳");
        assert_eq!(country_to_flag("123"), "🏳");
    }
}
