use std::{
    os::fd::AsFd,
    sync::{Arc, RwLock},
    thread::spawn,
};

use agave_afxdp::{
    device::{DeviceQueue, NetworkDevice, QueueId, RingSizes},
    socket::Socket,
    umem::{PageAlignedMemory, SliceUmem},
};
use anyhow::Context as _;
use aya::{
    maps::{xdp::XskMap, MapData},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use load_balancer::process::{
    free_tx_frames, insert_frames_fill_ring, process_packets, receive_packets, recycle_frames,
    release_cq_frames, send_packets, FramesManager, FRAME_COUNT, PACKETS_BATCH,
};
use log::{debug, warn};
use tokio::signal;

const FRAME_SIZE: usize = 4096;
const RING_SIZE: usize = 4096;

#[derive(Debug, Parser)]
struct Opt {
    /// Network interface to attach the XDP program to
    #[clap(short, long, default_value = "lo")]
    iface: String,

    /// Amount of queues to create sockets for
    #[clap(short, long, default_value_t = 1)]
    queues: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Here we will pass the channel to the async function that will shutdown the program
    // I might be using a oneshot channel for that purpose
    run_af_xdp_socket().await?;
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

async fn run_af_xdp_socket() -> anyhow::Result<()> {
    let opt: Opt = Opt::parse();

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
    let Opt { iface, queues } = opt;

    let program: &mut Xdp = ebpf.program_mut("load_balancer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    log::info!("XDP program attached to interface {}", iface);
    let xsk_map: Arc<RwLock<XskMap<MapData>>> = if let Some(map) = ebpf.take_map("XSK_SOCKS") {
        Arc::new(RwLock::new(map.try_into()?))
    } else {
        anyhow::bail!("failed to find XSK map");
    };

    let mut joinset = Vec::new();

    for queue in 0..queues {
        joinset.push(build_thread_tx_loop(queue, &iface, Arc::clone(&xsk_map))?);
    }

    for handle in joinset {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}

fn build_thread_tx_loop(
    queue: u64,
    iface: impl AsRef<str>,
    xsk_map: Arc<RwLock<XskMap<MapData>>>,
) -> anyhow::Result<std::thread::JoinHandle<anyhow::Result<()>>> {
    let iface = iface.as_ref().to_string();

    let task = move || {
        let mut aligned_memory = PageAlignedMemory::alloc(FRAME_SIZE, FRAME_COUNT)
            .expect("failed to allocate page aligned memory");

        let network_device = NetworkDevice::new(&iface).expect("failed to find the network device");

        let queue_id = QueueId(queue);
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

        {
            let mut xsk_map = xsk_map
                .write()
                .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
            xsk_map.set(queue as u32, socket.as_fd(), 0)?;
        }

        let mut frames_manager = FramesManager::new();

        let umem = socket.umem();
        frames_manager
            .insert_frames_from_umem(umem)
            .expect("failed to insert frames from umem. Space is full");

        let mut fill_ring = rx.fill;
        let mut completion_ring = tx.completion;

        insert_frames_fill_ring(&mut fill_ring, &mut frames_manager);
        fill_ring.sync(false);

        let mut rx_ring = rx.ring.unwrap();
        let mut tx_ring = tx.ring.unwrap();
        rx_ring.sync(false);

        loop {
            rx_ring.sync(false);
            tx_ring.sync(false);

            let available_packets = rx_ring.available();

            if available_packets == 0 {
                // Maybe RX is not receiving packets, so we can release completion ring frames and recycle fill ring frames in case there are any
                release_cq_frames(umem, &mut completion_ring);
                recycle_frames(umem, &mut fill_ring, &mut frames_manager)?;

                // Wake up if needed
                if fill_ring.needs_wakeup() {
                    fill_ring.wake()?;
                }
                continue;
            }

            let mut batch_size = PACKETS_BATCH.min(available_packets);

            batch_size = free_tx_frames(batch_size, &mut tx_ring);

            let received_pkts = receive_packets(batch_size, &mut rx_ring);

            let processed_pkts = process_packets(received_pkts, umem);

            send_packets(&mut tx_ring, processed_pkts, umem);

            rx_ring.commit();

            // Completion Ring
            release_cq_frames(umem, &mut completion_ring);

            // Frame recycling
            recycle_frames(umem, &mut fill_ring, &mut frames_manager)?;
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
    };
    let thread_handle = spawn(task);
    // });
    Ok(thread_handle)
}
