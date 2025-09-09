#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    // tcp::TcpHdr,
    // udp::UdpHdr,
};

#[xdp]
pub fn load_balancer(ctx: XdpContext) -> u32 {
    match try_load_balancer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_load_balancer(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    info!(&ctx, "TCP PACKET RECEIVED");

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            // let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            info!(&ctx, "TCP PACKET RECEIVED");
            Ok(xdp_action::XDP_PASS)
        }
        IpProto::Udp => Ok(xdp_action::XDP_PASS),
        _ => Err(()),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
