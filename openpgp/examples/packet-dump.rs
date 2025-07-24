use std::io::{self, Write as _};

use sequoia_openpgp::{
    self as openpgp,
    parse::{PacketParserBuilder, PacketParserResult, Parse},
};

fn main() -> openpgp::Result<()> {
    let path = std::env::args().nth(1).expect("usage: packet-dump <FILE>");

    let mut ppr = PacketParserBuilder::from_file(path)?
        .map(true)
        .buffer_unread_content()
        .build()?;

    let mut sink = io::stdout();
    let mut dirty = false;
    while let PacketParserResult::Some(pp) = ppr {
        if dirty {
            writeln!(sink)?;
        }
        dirty = true;

        pp.mapped_packet()?.dump()?.write_hex_to(&mut sink)?;
        ppr = pp.recurse()?.1;
    }

    Ok(())
}
