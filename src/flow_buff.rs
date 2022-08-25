use std::io::{Error, ErrorKind, Write};
use std::ops::Range;
use log::warn;

/// How far a future sequence number is allowed
const MAX_FORWARD_SEQ_JUMP: u64 = 100000;
/// The maximum buffer size allowed before a panic is called
const MAX_BUFFER_SIZE: usize = 1000000;

#[derive(Clone)]
pub struct FlowBuff {
    /// The buffer itself where the payloads are copied to
    data: Vec<u8>,
    /// Collection of filled payloads in buffer.
    //TODO actually do something with it
    data_filled_ranges: Vec<Range<usize>>,
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
            data: vec![],
            data_filled_ranges: vec![],
            // The ISN will be set later when SYN is detected
            initial_sequence_number: 0,
            byte_count: 0,
            packet_count: 0,
            wrap_around: 0,
            max_seq: 0,
            window_scale: 1,
        }
    }

    /// Check if this connection has bytes ready to process in one of the directions.
    /// This means that at least the number of requested bytes are present in a buffer from the current position.
    pub(crate) fn has_ready_bytes(&self, min_ready_bytes: usize) -> bool {
        let first_buffer = self.data_filled_ranges.get(0);
        return first_buffer.is_some() && first_buffer.unwrap().len() >= min_ready_bytes;
    }

    /// Answer if it has a significant number of bytes ready, or if the connection is closed and it has something to process.
    pub(crate) fn has_ready_buffer(&self, closed_connection: bool, min_ready_bytes: usize) -> bool {
        let first_buffer = self.data_filled_ranges.get(0);
        return first_buffer.is_some() && (closed_connection || first_buffer.unwrap().len() >= min_ready_bytes);
    }

    /// Return the buffer size
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Append a byte array to the buffer.
    /// The buffer is automatically extended if needed
    pub fn write_bytes(&mut self, bytes: &[u8], wpos: usize) {
        let size = bytes.len() + wpos;

        if size > self.data.len() {
            if size > MAX_BUFFER_SIZE {
                panic!("Test code does not allow large buffers. Asked for {} while max allowed is {}", size, MAX_BUFFER_SIZE)
            }
            self.resize(size);
        }

        let mut pos = wpos;
        for v in bytes {
            self.data[pos] = *v;
            pos += 1;
        }

        self.add_data_filled_range(wpos, wpos + bytes.len() - 1);
    }

    /// Add a range to the list of filled ranges
    /// _note_: Does not fill a gap between two others, or partial overlaps, if that happens
    fn add_data_filled_range(&mut self, start: usize, end_inclusive: usize) {
        for i in 0..self.data_filled_ranges.len() {
            let range = &mut self.data_filled_ranges[i];
            // If the new range is the 99% case that is an adjacent range with no gaps
            if range.end + 1 == start {
                range.end = end_inclusive;
                return;
            }
            // If the new range is a retransmission
            if range.start == start {
                if end_inclusive > range.end {
                    range.end = end_inclusive;
                }
                return;
            }
            // If the new range is the one that was missing right before
            if range.start == end_inclusive + 1 {
                range.start = start;
                return;
            }
        }
        // Did not find an overlapping range, so add a range
        // Happens with the first range, and normally should not happen often after that
        self.data_filled_ranges.push(start..end_inclusive);
    }

    /// Change the buffer size to size.
    ///
    /// _Note_: You cannot shrink a buffer with this method
    pub fn resize(&mut self, size: usize) {
        let diff = size - self.data.len();
        if diff > 0 {
            self.data.extend(std::iter::repeat(0).take(diff))
        }
    }

    /// Read a defined amount of raw bytes, or return an IO error if not enough bytes are available.
    pub fn read_bytes(&mut self, size: usize, rpos: usize) -> Result<Vec<u8>, Error> {
        if rpos + size > self.data.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Cannot read enough bytes from buffer"));
        }
        let range = rpos..(rpos + size);
        let mut res = Vec::<u8>::new();
        res.write_all(&self.data[range])?;
        Ok(res)
    }

    pub fn set_initial_sequence_number(&mut self, initial_sequence_number: u32) {
        self.initial_sequence_number = initial_sequence_number;
        self.max_seq = initial_sequence_number as u64;
    }

    /// Get the relative 0-based sequence number of the given TCP sequence.
    /// Handles a wrap around of TCP sequence numbers, that are only 32-bits.
    /// For example, the first payload byte is 0, the second is 1, etc.
    pub fn relative_seq(&self, seq: u32) -> u64 {
        (seq as u64) + (self.wrap_around as u64) * (u32::MAX as u64) - self.initial_sequence_number as u64 - 1u64
    }

    /// Calculate actual window size, given the published window size (up to 64KB) and the recorded window scaling (from SYN).
    pub fn scaled_window(&self, window: u16) -> u32 {
        (window as u32) * (self.window_scale as u32)
    }

    pub fn add_bytes(&mut self, tcp_seq: u32, byte_count: usize, data: &[u8]) {
        self.packet_count += 1;
        // Calculate the sequence number of the last byte
        if byte_count > 0 {
            self.byte_count += byte_count as u64;
            let last_seq: u64 = (tcp_seq as u64) + byte_count as u64 + (self.wrap_around as u64 * u32::MAX as u64);
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
            // Save to buffer
            // Typically all 3 length are identical- packet, packet header, packet data. TCP payload is 66 bytes less.
            let offset = data.len() - byte_count;
            if offset > 0 {
                let buf = &data[offset..data.len()];
                //TODO handle a future buffer-shift management
                let buffer_offset = self.relative_seq(tcp_seq) as usize;
                // Write the bytes and update the ranges control
                self.write_bytes(buf, buffer_offset);
            }
        }
    }
}