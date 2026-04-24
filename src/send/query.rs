use crate::QueryType;

const DNS_HEADER_SIZE: usize = 12;
const DNS_QUESTION_TRAILER_SIZE: usize = 5;

pub fn build_dns_query(domain: &str, query_type: QueryType, flag_id: u16) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(estimate_dns_query_size(domain));

    buffer.push((flag_id >> 8) as u8);
    buffer.push(flag_id as u8);
    buffer.extend_from_slice(&[0x01, 0x00]);
    buffer.extend_from_slice(&[0x00, 0x01]);
    buffer.extend_from_slice(&[0x00, 0x00]);
    buffer.extend_from_slice(&[0x00, 0x00]);
    buffer.extend_from_slice(&[0x00, 0x00]);

    for label in domain.split('.') {
        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }

    buffer.extend_from_slice(&[0x00]);
    buffer.extend_from_slice(&query_type.to_dns_code().to_be_bytes());
    buffer.extend_from_slice(&[0x00, 0x01]);

    buffer
}

pub fn estimate_dns_query_size(domain: &str) -> usize {
    let label_bytes = domain
        .split('.')
        .map(|label| label.len() + 1)
        .sum::<usize>();

    DNS_HEADER_SIZE + label_bytes + DNS_QUESTION_TRAILER_SIZE
}

#[cfg(test)]
mod tests {
    use super::{build_dns_query, estimate_dns_query_size};
    use crate::QueryType;

    #[test]
    fn estimate_dns_query_size_matches_encoded_query_length() {
        let domain = "www.api.example.com";
        let query = build_dns_query(domain, QueryType::A, 0x1234);

        assert_eq!(estimate_dns_query_size(domain), query.len());
    }
}
