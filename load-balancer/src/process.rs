use agave_afxdp::umem::{SliceUmemFrame, Umem};
use thiserror::Error;
pub const FRAME_COUNT: usize = 4096;

#[derive(Error, Debug)]
pub enum FramesError {
    #[error("No space available to insert frame")]
    NoSpace,
}
pub struct FramesManager<'a> {
    max_frames: usize,
    frame_available: usize,
    frames: Vec<Option<SliceUmemFrame<'a>>>,
}

impl<'a> FramesManager<'a> {
    pub fn new() -> Self {
        FramesManager {
            max_frames: FRAME_COUNT,
            frame_available: 0,
            frames: Vec::with_capacity(FRAME_COUNT),
        }
    }

    pub fn build_with_capacity(capacity: usize) -> Self {
        let mut frames = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            frames.push(None);
        }
        FramesManager {
            max_frames: capacity,
            frame_available: 0,
            frames,
        }
    }

    pub fn insert_frame(&mut self, frame: SliceUmemFrame<'a>) -> Result<(), FramesError> {
        if self.frame_available < self.max_frames {
            self.frames[self.frame_available] = Some(frame);
            self.frame_available += 1;
            Ok(())
        } else {
            Err(FramesError::NoSpace)
        }
    }

    pub fn get_free_frame(&mut self) -> Option<SliceUmemFrame<'a>> {
        if self.frame_available > 0 {
            self.frame_available -= 1;
            self.frames[self.frame_available].take()
        } else {
            None
        }
    }

    pub fn insert_frames_from_umem(
        &mut self,
        umem: &mut impl Umem<Frame = SliceUmemFrame<'a>>,
    ) -> Result<(), FramesError> {
        while let Some(frame) = umem.reserve() {
            self.insert_frame(frame)?;
        }
        Ok(())
    }
}

impl<'a> Iterator for FramesManager<'a> {
    type Item = SliceUmemFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_free_frame()
    }
}
