
use std::os::unix::thread;
use std::sync::mpsc;

use clap::Parser;
use rand::Rng;
use rsubdomain::input::Opts;
use rsubdomain::device;
use rsubdomain::recv;
use rsubdomain::send::SendDog;
use rand;
use rsubdomain::subdata::get_default_sub_next_data;

#[tokio::main]
async  fn main() {

    let opts = Opts::parse();

    println!("{:?}",opts.domain);

    let ether  = device::auto_get_devices();
    print!("{:?}",ether);
    let mut rng = rand::thread_rng();
    let flag_id: u16 = rng.gen_range(400..655);
    
    let (retry_chan,_) = mpsc::channel();
    let device_clone = ether.device.clone();
    let recv_thread = tokio::spawn(async move {
        recv::recv(device_clone, flag_id, retry_chan);
    });



    let recv_thread = tokio::spawn(async move {
        let senddog: SendDog = SendDog::new(ether, opts.resolvers, flag_id, true);
        let sub_domain_list = get_default_sub_next_data();

        for sub in *sub_domain_list{
            for _domain in opts.domain{
                let final_domain = sub.to_string();
                final_domain.push_str(".");
                final_domain =final_domain + &_domain;
                let dns_name = senddog.chose_dns();
                let (flagid2, scr_port) = sendog.BuildStatusTable(_domain, dnsname, 1);
                senddog.send(_domain, final_domain, scr_port, flagid2)
            }

        }
    });


    recv_thread.await.unwrap();


}
