
use rsubdomain::device;

#[tokio::main]
async  fn main() {
    device::auto_get_devices();
}