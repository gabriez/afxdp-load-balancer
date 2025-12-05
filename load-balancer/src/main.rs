use std::os::fd::AsFd;

use anyhow::Context as _;
use aya::{
    maps::{xdp::XskMap, MapError},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};

use agave_afxdp::{
    device::{DeviceQueue, NetworkDevice, QueueId, RingSizes},
    socket::Socket,
    umem::{Frame, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem},
};
use tokio::signal;

const FRAME_SIZE: usize = 4096;
const FRAME_COUNT: usize = 4096;
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

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/load-balancer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("load_balancer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // TODO: Maybe I could make this more dynamic by passing a string through
    // config or CLI argument to specify the map name?
    let mut xsk_map: XskMap<_> = if let Some(map) = ebpf.take_map("XSK_SOCKS") {
        map.try_into()?
    } else {
        anyhow::bail!("failed to find XSK map");
    };

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

    // For the moment and due to the limitations of my hardware, I'm unable to use more than one RX queue
    // however, I will refactor the code to support multiple queues in the future by using more threads.
    match xsk_map.set(0, socket.as_fd(), 0) {
        Ok(_) => {}
        Err(MapError::OutOfBounds { index, max_entries }) => {
            // I have to decide what will this do when we start to use threads. Should I panic or simply stop the thread?
            todo!("The XSK map is misconfigured: tried to access index {index} but the map only has {max_entries} entries.");
        }
        Err(err) => {
            return Err(err.into());
        }
    };
    let mut frames = vec![];
    let umem = socket.umem();
    while let Some(frame) = umem.reserve() {
        frames.push(frame);
    }
    let mut fill_ring = rx.fill;
    for frame in frames {
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
            println!("Received a packet of size: {}", packet.len());

            // let frame = packet.addr();
            // packet.len
            let slice_frame = SliceUmemFrame::from(packet);
            let frame_offset = slice_frame.offset();

            match tx_ring.write(slice_frame, 0) {
                Ok(_) => {}
                Err(_) => {
                    println!("TX ring is full, dropping packet");
                    umem.release(frame_offset);
                }
            }

            match tx_ring.wake() {
                Ok(_) => {}
                Err(_) => {
                    println!("Failed to wake TX ring");
                }
            }
        }
    }
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
