use etherparse::TcpHeaderSlice;

/// Return the most meaningful flag(s) in a TCP packet
/// By priority: RST,FIN,SYN/ACK,SYN or empty.
pub fn tcp_flags_to_string<'a>(tcp: &'a TcpHeaderSlice) -> &'a str {
    if tcp.rst() { return "RST"; }
    if tcp.fin() { return "FIN"; }
    if tcp.syn() {
        if tcp.ack() { return "SYN/ACK"; }
        return "SYN";
    }
    return "";
}