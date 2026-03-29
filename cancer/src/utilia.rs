// utilia.rs — functiones auxiliares retis et serializationis
//
// Scribere et legere numeros big-endian,
// mittere et legere plene per fluxum.
//
// Sine dependentiis externis.

use std::io::{self, Read, Write};

// --- serializatio big-endian ---

/// Scribe numerum 16-bitium in alveum big-endian.
pub fn scr16(p: &mut [u8], v: u16) {
    p[0] = (v >> 8) as u8;
    p[1] = v as u8;
}

/// Scribe numerum 24-bitium in alveum big-endian.
pub fn scr24(p: &mut [u8], v: u32) {
    p[0] = (v >> 16) as u8;
    p[1] = (v >> 8) as u8;
    p[2] = v as u8;
}

/// Lege numerum 16-bitium ex alveo big-endian.
pub fn leg16(p: &[u8]) -> u16 {
    (p[0] as u16) << 8 | p[1] as u16
}

/// Lege numerum 24-bitium ex alveo big-endian.
pub fn leg24(p: &[u8]) -> u32 {
    (p[0] as u32) << 16 | (p[1] as u32) << 8 | p[2] as u32
}

// --- lectio et scriptio plena ---

/// Mitte omnia data per fluxum. Iteratur donec omnia scripta sint.
pub fn mitte_plene(stream: &mut impl Write, data: &[u8]) -> io::Result<()> {
    stream.write_all(data)
}

/// Lege plene ex fluxu in alveum. Iteratur donec alveus plenus sit.
pub fn lege_plene(stream: &mut impl Read, alveus: &mut [u8]) -> io::Result<()> {
    stream.read_exact(alveus)
}
