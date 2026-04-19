use crate::QueryType;

pub fn build_dns_query(domain: &str, query_type: QueryType, flag_id: u16) -> Vec<u8> {
    let mut buffer = Vec::new();

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
