#[derive(Clone)]
pub struct FlowBuff {
    /// TCP initial sequence number (ISN) which is the one before the first payload byte
    initial_sequence_number: u32,
    /// Total number of TCP payload bytes so far
    /// May contain duplicates in case of retransmissions, overlaps etc.
    pub(crate) byte_count: u64,
    /// Number of packets. Can be empty packets or overlap sequences
    pub(crate) packet_count: u32,
}

impl FlowBuff {
    pub(crate) fn new() -> Self {
        Self {
            // The ISN will be set later when SYN is detected
            initial_sequence_number: 0,
            byte_count: 0,
            packet_count: 0,
        }
    }

    pub fn set_initial_sequence_number(&mut self, initial_sequence_number: u32) {
        self.initial_sequence_number = initial_sequence_number;
    }

    pub fn add_bytes(&mut self, tcp_seq: u32, byte_count: u64) {
        self.byte_count += byte_count;
        self.packet_count += 1;
    }
}