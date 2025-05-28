#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerCpuHashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::error;


#[map(name = "PER_CPU_DEVICE_PACKETS_MAP")]
static mut PER_CPU_DEVICE_PACKETS_MAP: PerCpuHashMap<[u8; 4], u32> =
    PerCpuHashMap::<[u8; 4], u32>::with_max_entries(128, 0);

#[tracepoint]
pub fn netif_receive(ctx: TracePointContext) -> u32 {
    match try_netif_receive(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_netif_receive(ctx: TracePointContext) -> Result<u32, u32> {
    /*  lots of guess work ! Still not sure it's correct

        sudo cat /sys/kernel/debug/tracing/events/net/netif_receive_skb/format
        name: netif_receive_skb
        ID: 1538
        format:
                field:unsigned short common_type;       offset:0;       size:2; signed:0;
                field:unsigned char common_flags;       offset:2;       size:1; signed:0;
                field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
                field:int common_pid;   offset:4;       size:4; signed:1;

                field:void * skbaddr;   offset:8;       size:8; signed:0;
                field:unsigned int len; offset:16;      size:4; signed:0;
                field:__data_loc char[] name;   offset:20;      size:4; signed:0;

        print fmt: "dev=%s skbaddr=%p len=%u", __get_str(name), REC->skbaddr, REC->len
     */
    const NETIF_RECEIVE_DEVICE_OFFSET: usize = 24;

    unsafe {
        let device_from_tracepoint = ctx.read_at::<[u8; 4]>(NETIF_RECEIVE_DEVICE_OFFSET);
        match device_from_tracepoint {
            Ok(device) => match PER_CPU_DEVICE_PACKETS_MAP.get_ptr_mut(&device) {
                Some(per_cpu_packet_counter) => {
                    *per_cpu_packet_counter += 1;
                }
                None => {
                    // 1st time we see this device/cpu pair - initialise to 0
                    let _ = PER_CPU_DEVICE_PACKETS_MAP.insert(&device, &0, 0);
                }
            },
            Err(_) => {
                error!(&ctx, "couldn't decode device");
            }
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
