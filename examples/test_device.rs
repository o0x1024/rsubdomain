
use rsubdomain::device;

#[tokio::main]
async fn main() {
    let ether = device::auto_get_devices().await;
    println!("{:?}",ether);
}