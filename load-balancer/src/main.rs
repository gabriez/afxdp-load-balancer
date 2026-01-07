use {
    agave_afxdp::{
        device::{DeviceQueue, NetworkDevice, QueueId, RingSizes},
        socket::{RingFull, Socket},
        tx_loop::kick,
        umem::{Frame, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem},
    },
    anyhow::Context as _,
    aya::{
        maps::{xdp::XskMap, MapData},
        programs::{Xdp, XdpFlags},
    },
    clap::Parser,
    load_balancer::{
        process::{FramesManager, FRAME_COUNT},
        tcp_connections_handler::{route_packet, shift_mac},
    },
    log::{debug, warn},
    std::{
        os::fd::AsFd,
        sync::{Arc, RwLock},
        thread::spawn,
    },
    tokio::signal,
};

const FRAME_SIZE: usize = 4096;
const RING_SIZE: usize = 4096;
const PACKETS_BATCH: usize = 64;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
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
    let Opt { iface } = opt;
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
    // Mover aligned_memory fuera del alcance inmediato
    // TODO: implement loop for multiple threads related to multiple queues

    let mut joinset = Vec::new();

    joinset.push(build_thread_tx_loop(0, &iface, Arc::clone(&xsk_map))?);

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
            xsk_map.set(0, socket.as_fd(), 0)?;
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

        // TODO: maybe i should move this operations into a separate async task to be able to handle ctrl-c properly and exit the program
        // Also i should implement a way to refill the fill ring when frames are consumed
        // And for the end, I must check if it's better to use parallel programming or not to improve performance.
        // Which libraries would be better for that purpose?
        // Tokio seems to be a good option, but maybe there are others more suitable for high-performance networking applications.
        // Rayon to work with parallel iterators?

        //
        loop {
            rx_ring.sync(false);
            tx_ring.sync(false);

            let mut packets_written = 0;

            let available_packets = rx_ring.available();
            if available_packets > 0 {
                let mut batch_size = PACKETS_BATCH.min(available_packets);
                while let Some(packet) = rx_ring.read()
                    && batch_size > 0
                {
                    batch_size -= 1;
                    let slice_frame = SliceUmemFrame::from(packet);

                    let available_tx = tx_ring.available();

                    // If by any reason tx_ring does not have any available frame, we're gonna kick it to try to free some space
                    // TODO: maybe I should add a retry here to avoid dropping packets in high load scenarios with a limit clearly to avoid
                    // endless loops
                    if available_tx == 0 {
                        tx_ring.commit();
                        kick(&tx_ring);
                        tx_ring.sync(false);
                    }

                    let frame_data = umem.map_frame_mut(&slice_frame);

                    let routed = route_packet(frame_data, [127, 0, 0, 1], 8000);

                    // Most of the time, packets will be routed, so maybe we can use likely here in the future to optimize branch prediction
                    if !routed {
                        umem.release(frame_ret.offset());
                        continue;
                    }

                    shift_mac(frame_data);

                    match tx_ring.write(slice_frame, 0) {
                        Ok(_) => {
                            packets_written += 1;
                        }
                        Err(RingFull(frame_ret)) => {
                            umem.release(frame_ret.offset());
                        }
                    }
                }

                if packets_written > 0 {
                    tx_ring.commit();

                    kick(&tx_ring);
                }

                rx_ring.commit();
            }

            // Completion Ring
            completion_ring.sync(false);
            while let Some(completed_frame) = completion_ring.read() {
                umem.release(completed_frame);
            }
            completion_ring.commit();

            // Frame recycling
            let available_frames = umem.available();

            if available_frames > 0 {
                if let Err(err) = frames_manager.insert_frames_from_umem(umem) {
                    warn!("Failed to insert frames from umem: {}", err);
                }

                insert_frames_fill_ring(&mut fill_ring, &mut frames_manager);

                if fill_ring.needs_wakeup() {
                    fill_ring.wake()?;
                }
                fill_ring.sync(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
    };
    let thread_handle = spawn(task);
    // });
    Ok(thread_handle)
}

// fn manage_frames() {}

#[inline(always)]
fn insert_frames_fill_ring<'a>(
    fill_ring: &mut agave_afxdp::device::RxFillRing<SliceUmemFrame<'a>>,
    frames_manager: &mut FramesManager<'a>,
) {
    while let Some(frame) = frames_manager.get_free_frame() {
        if let Err((frame_ret, err)) = fill_ring.write(frame) {
            warn!(
                "Failed to write frame to fill ring: {}. Returning frame",
                err
            );
            frames_manager
                .insert_frame(frame_ret)
                .expect("Failed to return frame to manager");
            break;
        }
    }

    fill_ring.commit();
}
