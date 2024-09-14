
use rsubdomain::device;

#[tokio::main]
async  fn main() {
    let mut s1 = 123;
    let s2 = &s1;


    println!("{}",s1);
    println!("{}",s2);
}