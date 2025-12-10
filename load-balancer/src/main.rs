use std::os::fd::AsFd;

use anyhow::Context as _;
use aya::{
    maps::{xdp::XskMap, MapError},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use load_balancer::process::{FramesManager, FRAME_COUNT};
#[rustfmt::skip]
use log::{debug, warn};

use agave_afxdp::{
    device::{DeviceQueue, NetworkDevice, QueueId, RingSizes},
    socket::{Socket, TxRing},
    umem::{Frame, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem},
};
use tokio::signal;

const FRAME_SIZE: usize = 4096;
const RING_SIZE: usize = 4096;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/load-balancer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("load_balancer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut xsk_map: XskMap<_> = if let Some(map) = ebpf.take_map("XSK_SOCKS") {
        map.try_into()?
    } else {
        anyhow::bail!("failed to find XSK map");
    };

    // Mover aligned_memory fuera del alcance inmediato
    let mut aligned_memory = PageAlignedMemory::alloc(FRAME_SIZE, FRAME_COUNT)
        .expect("failed to allocate page aligned memory");

    let network_device = NetworkDevice::new(&iface).expect("failed to find the network device");

    let queue_id = QueueId(0);
    let ring_sizes = RingSizes {
        rx: RING_SIZE,
        tx: RING_SIZE,
    };

    let device_queue = DeviceQueue::new(network_device.if_index(), queue_id, Some(ring_sizes));
    let umem = SliceUmem::new(&mut aligned_memory, FRAME_SIZE as u32)?;

    let (mut socket, rx, tx) = Socket::new(
        device_queue,
        umem,
        false,
        RING_SIZE,
        RING_SIZE,
        RING_SIZE,
        RING_SIZE,
    )?;

    match xsk_map.set(0, socket.as_fd(), 0) {
        Ok(_) => {}
        Err(MapError::OutOfBounds { index, max_entries }) => {
            todo!("The XSK map is misconfigured: tried to access index {index} but the map only has {max_entries} entries.");
        }
        Err(err) => {
            return Err(err.into());
        }
    };

    let mut frames_manager = FramesManager::new();

    let umem = socket.umem();
    frames_manager
        .insert_frames_from_umem(umem)
        .expect("failed to insert frames from umem");

    let mut fill_ring = rx.fill;

    for frame in frames_manager {
        fill_ring
            .write(frame)
            .expect("failed to write frame to fill ring");
    }
    fill_ring.sync(true);

    let mut rx_ring = rx.ring.unwrap();
    rx_ring.sync(false);
    let mut tx_ring = tx.ring.unwrap();

    println!(
        "RX ring available and capacity frames: {} {}",
        rx_ring.available(),
        rx_ring.capacity()
    );
    loop {
        rx_ring.sync(false);

        while let Some(packet) = rx_ring.read() {
            let slice_frame = SliceUmemFrame::from(packet);
            let frame_offset = slice_frame.offset();

            match tx_ring.write(slice_frame, 0) {
                Ok(_) => {}
                Err(_) => {
                    println!("TX ring is full, dropping packet");
                    umem.release(frame_offset);
                }
            }
            tx_ring.commit();

            kick(&tx_ring);

            match tx_ring.wake() {
                Ok(_) => {
                    println!("TX ring waked");
                }
                Err(_) => {
                    println!("Failed to wake TX ring");
                }
            }
            rx_ring.sync(true);
        }
    }
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

// With some drivers, or always when we work in SKB mode, we need to explicitly kick the driver once
// we want the NIC to do something.
#[inline(always)]
fn kick(ring: &TxRing<SliceUmemFrame<'_>>) {
    if !ring.needs_wakeup() {
        return;
    }

    if let Err(e) = ring.wake() {
        kick_error(e);
    }
}

#[inline(never)]
fn kick_error(e: std::io::Error) {
    match e.raw_os_error() {
        // these are non-fatal errors
        Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN) => {}
        // this can temporarily happen with some drivers when changing
        // settings (eg with ethtool)
        Some(libc::ENETDOWN) => {
            log::warn!("network interface is down")
        }
        // we should never get here, hopefully the driver recovers?
        _ => {
            log::error!("network interface driver error: {e:?}");
        }
    }
}
