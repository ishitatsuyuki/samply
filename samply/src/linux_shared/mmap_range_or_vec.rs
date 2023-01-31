use std::ops::Deref;
use std::sync::Arc;

use framehop::RvaMapper;
use memmap2::Mmap;
use object::read::pe::PeFile64;

#[derive(Clone)]
pub enum MmapRangeOrVec {
    MmapRange(Arc<Mmap>, (usize, usize)),
    Vec(Arc<Vec<u8>>),
}

impl MmapRangeOrVec {
    pub fn new_mmap_range(mmap: Arc<Mmap>, start: u64, size: u64) -> Option<MmapRangeOrVec> {
        let start = usize::try_from(start).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        if end <= mmap.len() {
            Some(Self::MmapRange(mmap, (start, size)))
        } else {
            None
        }
    }
}

impl Deref for MmapRangeOrVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            MmapRangeOrVec::MmapRange(mmap, (start, size)) => &mmap[*start..][..*size],
            MmapRangeOrVec::Vec(vec) => &vec[..],
        }
    }
}

pub struct MmapRvaMapper {
    mmap: Arc<Mmap>,
}

impl MmapRvaMapper {
    pub fn new(mmap: Arc<Mmap>) -> Self {
        Self { mmap }
    }
}

impl RvaMapper for MmapRvaMapper {
    fn map(&self, rva: u32) -> Option<&[u8]> {
        let file = PeFile64::parse(&self.mmap[..]).unwrap();
        let section = file.section_table();
        section.pe_data_at(&self.mmap[..], rva)
    }
}
