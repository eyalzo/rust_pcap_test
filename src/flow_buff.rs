use log::warn;

/// A far a future sequence number is allowed
const MAX_FORWARD_SEQ_JUMP: u64 = 100000;

#[derive(Clone)]
pub struct FlowBuff {
    /// TCP initial sequence number (ISN) which is the one before the first payload byte
    initial_sequence_number: u32,
    /// Max sequence seen so far, for total unique payload calculation.
    /// Can be higher than 2^32 because of wrap around(s)
    max_seq: u64,
    /// Number of times the sequence numbers were wrapped around (4GB each time)
    wrap_around: usize,
    /// Total number of TCP payload bytes so far
    /// May contain duplicates in case of retransmissions, overlaps etc.
    pub(crate) byte_count: u64,
    /// Number of packets. Can be empty packets or overlap sequences
    pub(crate) packet_count: u32,
    /// TCP window scale multiplier (from 1 to 2^14) to multiply the transmitted window size (up to 64KB).
    /// By using the window scale option, the receive window size may be increased up to a maximum value of 1,073,725,440.
    pub(crate) window_scale: u16,
}

impl FlowBuff {
    pub(crate) fn new() -> Self {
        Self {
            // The ISN will be set later when SYN is detected
            initial_sequence_number: 0,
            byte_count: 0,
            packet_count: 0,
            wrap_around: 0,
            max_seq: 0,
            window_scale: 1,
        }
    }

    pub fn set_initial_sequence_number(&mut self, initial_sequence_number: u32) {
        self.initial_sequence_number = initial_sequence_number;
        self.max_seq = initial_sequence_number as u64;
    }

    pub fn relative_seq(&self, seq: u32) -> u64 {
        (seq as u64) + (self.wrap_around as u64) * (u32::MAX as u64) - self.initial_sequence_number as u64 - 1u64
    }

    /// Calculate actual window size, given the published window size (up to 64KB) and the recorded window scaling (from SYN).
    pub fn scaled_window(&self, window: u16) -> u32 {
        (window as u32) * (self.window_scale as u32)
    }

    pub fn add_bytes(&mut self, tcp_seq: u32, byte_count: u64) {
        self.packet_count += 1;
        // Calculate the sequence number of the last byte
        if byte_count > 0 {
            self.byte_count += byte_count;
            let last_seq: u64 = (tcp_seq as u64) + byte_count + (self.wrap_around as u64 * u32::MAX as u64);
            // Check if this sequence number creates a wrap around that makes sense
            if last_seq < self.max_seq && (last_seq + u32::MAX as u64) > self.max_seq && (last_seq + u32::MAX as u64 - MAX_FORWARD_SEQ_JUMP) <= self.max_seq {
                self.wrap_around += 1;
                self.max_seq = last_seq + u32::MAX as u64;
            } else if last_seq - MAX_FORWARD_SEQ_JUMP < self.max_seq {
                self.max_seq = last_seq;
            } else {
                warn!("Conn seq error: ISN {}, max {}, packet seq {} len {}, calc last {}",
                    self.initial_sequence_number, self.max_seq, tcp_seq, byte_count, last_seq);
            }
        }
    }
}