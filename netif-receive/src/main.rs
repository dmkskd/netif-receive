use aya::{maps::PerCpuHashMap, programs::TracePoint};
use aya_log::{EbpfLogger};
use env_logger;

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netif-receive"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut TracePoint = ebpf.program_mut("netif_receive").unwrap().try_into()?;
    program.load()?;
    program.attach("net", "netif_receive_skb")?;
    let _logger = EbpfLogger::init(&mut ebpf);

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;


    // display the results
    println!("\n");
    let per_cpu_map : PerCpuHashMap<_, [u8;4], u32> = PerCpuHashMap::try_from(ebpf.map_mut("PER_CPU_DEVICE_PACKETS_MAP").unwrap())?;
     for result in per_cpu_map.iter() {
        let (key, value) = result?;
        let device = key.iter().filter(|b| **b !=0 ).map(|&b| b as char).collect::<String>();
        println!("@[{:?}]", &device);
        for (cpu, packets) in value.iter().enumerate() {
            println!("|{:?}\t\t{:?}|", cpu, packets);
        }
     }

    Ok(())
}
