use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use rand;
use rand::Rng;
use rsubdomain::input::Opts;
use rsubdomain::send::SendDog;
use rsubdomain::structs::{RetryStruct, LOCAL_STATUS};
use rsubdomain::subdata;
use rsubdomain::{device, handle};
use rsubdomain::{recv, send};

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    println!("{:?}", opts.domain);
    let ether = device::auto_get_devices();
    println!("{:?}", ether);
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let flag_id: u16 = rng.gen_range(400..655);
    let device_clone = ether.device.clone();
    let running = Arc::new(AtomicBool::new(true));

    let senddog = Arc::new(Mutex::new(SendDog::new(ether, opts.resolvers, flag_id)));
    let sub_domain_list = subdata::get_default_sub_next_data();

    let (dns_send, dns_recv) = mpsc::channel();
    let (retry_send, retry_recv): (
        mpsc::Sender<Arc<RwLock<RetryStruct>>>,
        mpsc::Receiver<Arc<RwLock<RetryStruct>>>,
    ) = mpsc::channel();

    {
        //网卡收包
        let running_clone: Arc<AtomicBool> = running.clone();
        tokio::spawn(async move {
            recv::recv(device_clone, dns_send, running_clone);
        });
    }

    {
        let running_clone: Arc<AtomicBool> = running.clone();
        //处理收到的包
        tokio::spawn(async move {
            handle::handle_dns_packet(dns_recv, opts.print_status, flag_id, running_clone,opts.slient);
        });
    }

    let mut count = 0;
    match opts.file {
        Some(path) => {
            let file = File::open(&path).unwrap();
            let reader = io::BufReader::new(file);
            for line in reader.lines() {
                if let Ok(sub) = line {
                    for _domain in opts.domain.clone() {
                        let mut senddog = senddog.try_lock().unwrap();
                        let mut final_domain = sub.clone();
                        final_domain.push_str(".");
                        final_domain = final_domain + &_domain;
                        let dns_name = senddog.chose_dns();
                        let (flagid2, scr_port) =
                            senddog.build_status_table(final_domain.as_str(), dns_name.as_str(), 1);
                        senddog.send(final_domain, dns_name, scr_port, flagid2);
                        count += 1;
                    }
                }
            }
        }
        None => {
            for sub in *sub_domain_list {
                for _domain in opts.domain.clone() {
                    let mut senddog = senddog.try_lock().unwrap();
                    let mut final_domain = sub.to_string();
                    final_domain.push_str(".");
                    final_domain = final_domain + &_domain;
                    let dns_name = senddog.chose_dns();
                    let (flagid2, scr_port) =
                        senddog.build_status_table(final_domain.as_str(), dns_name.as_str(), 1);
                    senddog.send(final_domain, dns_name, scr_port, flagid2);
                    count += 1;
                }
            }
        }
    }
    println!("subdomain count:{}", count);

    let senddog_clone = Arc::clone(&senddog);
    {
        let running: Arc<AtomicBool> = running.clone();
        //处理超时的域名
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let mut is_delay = true;
                let mut datas = Vec::new();
                match LOCAL_STATUS.write() {
                    Ok(mut local_status) => {
                        let max_length = (1000000 / 10) as usize;
                        datas = local_status.get_timeout_data(max_length);
                        is_delay = datas.len() > 100;
                    }
                    Err(_) => (),
                }

                for local_data in datas {
                    let index = local_data.index;
                    let mut value = local_data.v;

                    if value.retry >= 5 {
                        // 处理失败的索引
                        match LOCAL_STATUS.write() {
                            Ok(mut local_status) => {
                                match local_status.search_from_index_and_delete(index as u32) {
                                    Ok(data) => {
                                        println!("main delete:{:?}", data.v);
                                    }
                                    Err(_) => (),
                                }
                                continue;
                            }
                            Err(_) => (),
                        }
                    }
                    let senddog = senddog_clone.lock().unwrap();
                    value.retry += 1;
                    value.time = chrono::Utc::now().timestamp() as u64;
                    value.dns = senddog.chose_dns(); // 假设有一个选择 DNS 的函数
                    let value_c = value.clone();
                    {
                        match LOCAL_STATUS.write() {
                            Ok(mut local_status) => {
                                local_status.search_from_index_and_delete(index);
                                local_status.append(value_c, index);
                            }
                            Err(_) => {}
                        }
                    }

                    let (flag_id, src_port) = send::generate_flag_index_from_map(index as usize); // 假设有这个函数
                    let retry_struct = RetryStruct {
                        domain: value.domain,
                        dns: value.dns,
                        src_port,
                        flag_id,
                        domain_level: value.domain_level as usize,
                    };
                    // println!("{:?}",retry_struct);
                    //发送重试结构体到通道
                    let _ = retry_send
                        .send(Arc::new(RwLock::new(retry_struct)))
                        .unwrap();

                    if is_delay {
                        let sleep_duration = rand::thread_rng().gen_range(100..=400);
                        sleep(Duration::from_micros(sleep_duration));
                    }
                }
            }
        });
    }

    {
        let running: Arc<AtomicBool> = running.clone();
        let senddog = Arc::clone(&senddog);
        //超时的重发
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                match retry_recv.recv() {
                    Ok(res) => {
                        let rety_data = res.read().unwrap();
                        let senddog = senddog.lock().unwrap();

                        senddog.send(
                            rety_data.domain.clone(),
                            rety_data.dns.clone(),
                            rety_data.src_port,
                            rety_data.flag_id,
                        )
                    }
                    Err(_) => (),
                }
            }
        });
    }

    loop {
        match LOCAL_STATUS.read() {
            Ok(local_status) => {
                if local_status.empty() {
                    break;
                }
            }
            Err(_) => (),
        }
        sleep(Duration::from_millis(1000))
    }
    running.store(false, Ordering::Relaxed);
    println!("done")
}
