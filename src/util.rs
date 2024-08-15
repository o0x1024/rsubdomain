use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::iter::repeat_with;

#[allow(dead_code)]
fn random_str(n: usize) -> String {
    let mut rng = thread_rng();
    // 生成一个长度为 n 的随机字符串
    repeat_with(|| rng.sample(Alphanumeric) as char)
        .take(n)
        .collect()
}