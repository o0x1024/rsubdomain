use lazy_static::lazy_static;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, RwLock,
};

use crate::{local_struct::LocalStruct, stack::Stack};

static RECV_INDEX: AtomicU8 = AtomicU8::new(0);
static FAILD_INDEX: AtomicU8 = AtomicU8::new(0);
static SEND_INDEX: AtomicU8 = AtomicU8::new(0);
static SUCCESS_INDEX: AtomicU8 = AtomicU8::new(0);

// 重发状态数据结构
#[derive(Debug)]
pub struct RetryStruct {
    pub domain: String,
    pub dns: String,
    pub src_port: u16,
    pub flag_id: u16,
    pub domain_level: usize,
}

lazy_static! {
    pub static ref LOCAL_STACK: RwLock<Stack<usize>> = RwLock::new(Stack::new());
}

lazy_static! {
    pub static ref LOCAL_STATUS: Arc<RwLock<LocalStruct>> =
        Arc::new(RwLock::new(LocalStruct::new()));
}

pub fn get_recv_index() -> u8 {
    RECV_INDEX.load(Ordering::Relaxed)
}

pub fn set_recv_index(value: u8) {
    RECV_INDEX.store(value, Ordering::Relaxed);
}

pub fn get_faild_index() -> u8 {
    FAILD_INDEX.load(Ordering::Relaxed)
}

pub fn set_faild_index(value: u8) {
    FAILD_INDEX.store(value, Ordering::Relaxed);
}

pub fn get_send_index() -> u8 {
    SEND_INDEX.load(Ordering::Relaxed)
}

pub fn set_send_index(value: u8) {
    SEND_INDEX.store(value, Ordering::Relaxed);
}

pub fn get_success_index() -> u8 {
    SUCCESS_INDEX.load(Ordering::Relaxed)
}

pub fn set_success_index(value: u8) {
    SUCCESS_INDEX.store(value, Ordering::Relaxed);
}
