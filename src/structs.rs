use crate::QueryType;

// 重发状态数据结构
#[derive(Debug)]
pub struct RetryStruct {
    pub domain: String,
    pub dns: String,
    pub query_type: QueryType,
    pub src_port: u16,
    pub flag_id: u16,
}
