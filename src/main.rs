use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use rand;
use rand::Rng;
use rsubdomain::device;
use rsubdomain::input::Opts;
use rsubdomain::local_struct::LOCAL_STATUS;
use rsubdomain::recv;
use rsubdomain::send::SendDog;
use rsubdomain::subdata::get_default_sub_next_data;

#[tokio::main]
async fn main() {
    let opts = Opts::parse();

    println!("{:?}", opts.domain);

    let ether = device::auto_get_devices();
    print!("{:?}", ether);

    sleep(Duration::from_millis(500));
    let mut rng = rand::thread_rng();
    let flag_id: u16 = rng.gen_range(400..655);

    let (retry_chan, _) = mpsc::channel();
    let device_clone = ether.device.clone();
    
    tokio::spawn(async move {
        recv::recv(device_clone, flag_id, retry_chan);
    });

    let senddog: SendDog = SendDog::new(ether, opts.resolvers, flag_id, true);
    let sub_domain_list = get_default_sub_next_data();

    for sub in *sub_domain_list {
        for _domain in opts.domain.clone() {
            let mut send_dog_clone = senddog.clone();

            let mut final_domain = sub.to_string();
            final_domain.push_str(".");
            final_domain = final_domain + &_domain;
            let dns_name = senddog.chose_dns();
            let (flagid2, scr_port) = send_dog_clone.build_status_table(final_domain.as_str(), dns_name.as_str(), 1);
            send_dog_clone.send(final_domain, dns_name, scr_port, 500)
        }
    }

    let  local_status = LOCAL_STATUS.read().unwrap();
    loop {
        if local_status.empty() {
            break;
        }
        sleep(Duration::from_millis(723))
    }
}
