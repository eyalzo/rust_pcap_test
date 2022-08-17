#[derive(Clone)]
pub struct FlowBuff {
    /// Total number of TCP payload bytes so far
    /// May contain duplicates in case of retransmissions, overlaps etc.
    pub(crate) byte_count: u64,
    /// Number of packets. Can be empty packets or overlap sequences
    pub(crate) packet_count: u32,
}

impl FlowBuff {
    pub(crate) fn new() -> Self {
        Self {
            byte_count: 0,
            packet_count: 0,
        }
    }

    pub fn add_bytes(&mut self, byte_count: u64) {
        self.byte_count += byte_count;
        self.packet_count += 1;
    }
}