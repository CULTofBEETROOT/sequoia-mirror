//! Mapped packets, the foundation for packet dumps.

use std::{
    collections::BTreeMap,
    io,
};

use crate::{
    Result,
    self as openpgp,
    fmt::hex,
    packet,
    packet::header::{BodyLength, CTB},
    parse::map::{Field, Map},
    parse::map,
    serialize::MarshalInto,
    types::*,
};

/// Represents a field with a prefix length.
#[derive(Clone, Debug)]
pub struct LengthPrefixedField<'a> {
    /// The length field.
    length: Field<'a>,

    /// The value field counted by the length.
    field: Field<'a>,
}
assert_send_and_sync!(LengthPrefixedField<'_>);

impl<'a> LengthPrefixedField<'a> {
    /// Creates a new counted field.
    fn new(length: Field<'a>, field: Field<'a>) -> Self {
        LengthPrefixedField { length, field }
    }

    /// Returns the length.
    pub fn length(&self) -> Field<'a> {
        self.length.clone()
    }

    /// Returns the field counted by the length.
    pub fn field(&self) -> Field<'a> {
        self.field.clone()
    }
}

/// Represents a field with a prefix length.
#[derive(Clone, Debug)]
pub struct LengthPrefixedOptionalField<'a> {
    /// The length field.
    length: Field<'a>,

    /// The value field counted by the length.
    field: Option<Field<'a>>,
}
assert_send_and_sync!(LengthPrefixedOptionalField<'_>);

impl<'a> LengthPrefixedOptionalField<'a> {
    /// Creates a new counted field.
    fn new(length: Field<'a>, field: Option<Field<'a>>) -> Self {
        LengthPrefixedOptionalField { length, field }
    }

    /// Returns the length.
    pub fn length(&self) -> Field<'a> {
        self.length.clone()
    }

    /// Returns the field counted by the length.
    pub fn field(&self) -> Option<Field<'a>> {
        self.field.clone()
    }
}

/// A mapped packet.
///
/// This type closely matches [`crate::packet::Packet`], but the packet
/// types can only be used for inspection.
pub enum Packet<'m> {
    /// Signature packet.
    Signature(Signature<'m>),

    /// Literal data packet.
    Literal(Literal<'m>),

    /// XXX
    Other(&'m Map, &'m packet::Header),
}

impl<'m> Packet<'m> {
    /// Returns the header of the packet.
    pub fn header(&self) -> Header<'m> {
        match self {
            Packet::Signature(p) => p.header(),
            Packet::Literal(p) => p.header(),
            Packet::Other(m, h) => Header { m: *m, h: *h },
        }
    }

    pub fn map(&self) -> &'m Map {
        self.header().m
    }
}


/// A packet's header.
///
/// This type closely matches [`crate::packet::Header`], but can only be
/// used for inspection.
pub struct Header<'m> {
    m: &'m Map,
    h: &'m packet::Header,
}

impl<'m> Header<'m> {
    /// Returns the packet's CTB.
    pub fn ctb(&self) -> (Field<'m>, &packet::header::CTB) {
        (self.m.find("CTB").unwrap(), self.h.ctb())
    }

    /// Returns the packet's length.
    pub fn length(&self) -> (Field<'m>, &packet::header::BodyLength) {
        (self.m.find("length").unwrap(), self.h.length())
    }

    /// Dumps the header.
    fn dump(&self, fields: &mut Fields<'m>) -> Result<()> {
        let (e, v) = self.ctb();
        fields.insert(e, "Packet", match v {
            CTB::New(c) => format!("{}", c.tag()),
            CTB::Old(c) => format!("{} (legacy CTB)", c.tag()),
        });

        let (e, v) = self.length();
        fields.insert(e, "Length", match v {
            BodyLength::Full(n) =>
                format!("{} bytes", n),
            BodyLength::Partial(n) =>
                format!("{} bytes in first chunk", n),
            BodyLength::Indeterminate =>
                "Indeterminate".into(),
        });

        Ok(())
    }
}


macro_rules! mapped_packet {
    ($p:ident) => {
        #[doc = concat!("A ", stringify!($p), " packet.")]
        ///
        /// This type closely matches
        #[doc = concat!("[`crate::packet::prelude::", stringify!($p), "`], ")]
        /// but can only be used for inspection.
        pub struct $p<'m> {
            m: &'m Map,
            h: &'m packet::Header,
            p: &'m packet::prelude::$p,
        }

        impl<'m> $p<'m> {
            pub(crate) fn new(m: &'m Map, h: &'m packet::Header, p: &'m packet::prelude::$p) -> Self {
                $p { m, h, p }
            }

            /// Returns the header of the packet.
            fn header(&self) -> Header<'m> {
                Header { m: self.m, h: self.h }
            }
        }
    }
}

/// A signature subpacket area.
///
/// This type closely matches
/// [`crate::packet::signature::subpacket::SubpacketArea`], but can
/// only be used for inspection.
pub struct SubpacketArea<'m> {
    m: &'m Map,
    map_offset: usize,
    a: &'m packet::signature::subpacket::SubpacketArea,
}

impl<'m> SubpacketArea<'m> {
    /// Iterates over the subpackets.
    pub fn iter<'s>(&'s self) -> impl Iterator<Item = (Field<'m>, Subpacket<'m>)> + Send + Sync + 's {
        let mut offset = Some(self.map_offset);
        self.a.iter()
            .map(move |p| {
                let o = offset.unwrap();
                let f = self.m.iter().nth(o).unwrap();
                let p = Subpacket {
                    m: self.m,
                    map_offset: o,
                    p,
                };

                // Update offset to point to the next subpacket, if any.
                offset = self.m.iter().enumerate().skip(o + 1)
                    .find_map(|(i, e)|
                              (e.name() == "subpacket length").then_some(i));

                (f, p)
            })
    }
}

/// A signature subpacket.
///
/// This type closely matches
/// [`crate::packet::signature::subpacket::Subpacket`], but can only
/// be used for inspection.
pub struct Subpacket<'m> {
    m: &'m Map,
    map_offset: usize,
    p: &'m packet::signature::subpacket::Subpacket,
}

impl<'m> Subpacket<'m> {
    /// Returns whether the critical bit is set.
    pub fn critical(&self) -> (Field<'m>, bool) {
        (self.m.find_from(self.map_offset, "subpacket tag").unwrap(),
         self.p.critical())
    }

    /// Returns the Subpacket's tag.
    pub fn tag(&self) -> (Field<'m>, packet::signature::subpacket::SubpacketTag) {
        (self.m.find_from(self.map_offset, "subpacket tag").unwrap(),
         self.p.value().tag())
    }

    /// Returns the Subpacket's value.
    pub fn value(&self) -> (Field<'m>, &packet::signature::subpacket::SubpacketValue) {
        (self.m.iter().nth(2).unwrap(), self.p.value())
    }
}

pub enum Signature<'m> {
    V4(Signature4<'m>),
    V6(Signature6<'m>),
}

impl<'m> Signature<'m> {
    /// Returns the header of the packet.
    fn header(&self) -> Header<'m> {
        match self {
            Signature::V4(p) => p.header(),
            Signature::V6(p) => p.header(),
        }
    }

    /// Dumps the packet.
    fn dump(&self, fields: &mut Fields<'m>) -> Result<()> {
        match self {
            Signature::V4(p) => p.dump(fields),
            Signature::V6(p) => p.dump(fields),
        }
    }
}

mapped_packet!(Signature4);

impl<'m> Signature4<'m> {
    /// Gets the version.
    pub fn version(&self) -> (Field<'m>, u8) {
        (self.m.find("version").unwrap(), self.p.version())
    }

    /// Gets the signature type.
    ///
    /// This function is called `typ` and not `type`, because `type`
    /// is a reserved word.
    pub fn typ(&self) -> (Field<'m>, SignatureType) {
        (self.m.find("type").unwrap(), self.p.typ())
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> (Field<'m>, PublicKeyAlgorithm) {
        (self.m.find("pk_algo").unwrap(), self.p.pk_algo())
    }

    /// Gets the hash algorithm.
    pub fn hash_algo(&self) -> (Field<'m>, HashAlgorithm) {
        (self.m.find("hash_algo").unwrap(), self.p.hash_algo())
    }

    /// Gets a reference to the hashed area.
    pub fn hashed_area(&self) -> (Field<'m>, SubpacketArea<'m>) {
        let i = self.m.iter().enumerate()
            .find_map(|(i, e)| (e.name() == "hashed_area_len").then_some(i))
            .unwrap();

        (self.m.iter().nth(i).unwrap(), SubpacketArea {
            m: self.m,
            map_offset: i + 1,
            a: self.p.hashed_area(),
        })
    }

    /// Gets a reference to the unhashed area.
    pub fn unhashed_area(&self) -> (Field<'m>, SubpacketArea<'m>) {
        let i = self.m.iter().enumerate()
            .find_map(|(i, e)| (e.name() == "unhashed_area_len").then_some(i))
            .unwrap();

        (self.m.iter().nth(i).unwrap(), SubpacketArea {
            m: self.m,
            map_offset: i + 1,
            a: self.p.unhashed_area(),
        })
    }

    /// Gets the digest prefix.
    pub fn digest_prefix(&self) -> (Field<'m>, &[u8; 2]) {
        (self.m.find("digest_prefix").unwrap(), self.p.digest_prefix())
    }

    /// Dumps the packet.
    fn dump(&self, fields: &mut Fields<'m>) -> Result<()> {
        let (f, v) = self.version();
        fields.insert(f, "Version", v);

        let (f, v) = self.typ();
        fields.insert(f, "Type", v);

        let (f, v) = self.pk_algo();
        fields.insert(f, "Public-key algo", v);

        let (f, v) = self.hash_algo();
        fields.insert(f, "Hash algo", v);

        let (f, subpackets) = self.hashed_area();
        fields.insert(f, "Hashed subpackets",
                      format!("{} ({} bytes)",
                              subpackets.iter().count(),
                              subpackets.a.serialized_len()));

        for (f, p) in subpackets.iter() {
            fields.insert(f, "Subpacket length",
                          format!("{} bytes", p.p.serialized_len() - 1));

            let (f, v) = p.tag();
            fields.insert(f, "Subpacket", if p.p.critical() {
                format!("{} (critical)", v)
            } else {
                v.to_string()
            });
        }

        let (f, subpackets) = self.unhashed_area();
        fields.insert(f, "Unhashed subpackets",
                      format!("{} ({} bytes)",
                              subpackets.a.iter().count(),
                              subpackets.a.serialized_len()));

        let (f, v) = self.digest_prefix();
        fields.insert(f, "Digest prefix", crate::fmt::hex::encode(v));

        Ok(())
    }
}

mapped_packet!(Signature6);

impl<'m> Signature6<'m> {
    /// Dumps the packet.
    fn dump(&self, fields: &mut Fields<'m>) -> Result<()> {
        Ok(())
    }
}

mapped_packet!(Literal);

impl<'m> Literal<'m> {
    /// Gets the Literal packet's content disposition.
    pub fn format(&self) -> (Field<'m>, DataFormat) {
        (self.m.find("format").unwrap(), self.p.format())
    }

    /// Gets the literal packet's filename.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn filename(&self) -> (LengthPrefixedOptionalField<'m>, Option<&[u8]>) {
        (LengthPrefixedOptionalField::new(self.m.find("filename_len").unwrap(),
                                          self.m.find("filename")),
         self.p.filename())
    }

    /// Gets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn date(&self) -> (Field<'m>, Option<std::time::SystemTime>) {
        (self.m.find("date").unwrap(), self.p.date())
    }

    /// Gets a reference to the this packet's body.
    pub fn body(&self) -> (Field<'m>, &[u8]) {
        (self.m.find("body").unwrap(), self.p.body())
    }

    /// Dumps the packet.
    fn dump(&self, fields: &mut Fields<'m>) -> Result<()> {
        let (e, f) = self.format();
        fields.insert(e, "Format", f);

        if let (lpf, Some(filename)) = self.filename() {
            fields.insert(lpf.length(),
                          "Filename length",
                          format!("{} bytes", filename.len()));

            if let Some(f) = lpf.field() {
                fields.insert(f, "Filename",
                              String::from_utf8_lossy(filename));
            }
        }
        if let (e, Some(timestamp)) = self.date() {
            fields.insert(
                e, "Time",
                Timestamp::try_from(timestamp).expect("representable"));
        }

        Ok(())
    }
}


pub struct Fields<'map> {
    f: BTreeMap<usize, (map::Field<'map>, &'map str, String)>,
}

impl<'map> Fields<'map> {
    fn insert<V>(&mut self, f: map::Field<'map>, label: &'map str, value: V)
    where
        V: ToString,
    {
        self.f.insert(f.offset(), (f, label, value.to_string()));
    }

    fn iter(&self) -> impl Iterator<Item = &(map::Field<'map>, &'map str, String)> {
        self.f.values()
    }

    pub fn write_to(&self, sink: &mut dyn io::Write) -> openpgp::Result<()> {
        for (f, l, v) in self.iter() {
            if ! v.is_empty() {
                if f.offset() > 0 {
                    write!(sink, "    ")?;
                }

                writeln!(sink, "{}: {}", l, v)?;
            }
        }

        Ok(())
    }

    pub fn write_hex_to(&self, sink: &mut dyn io::Write) -> openpgp::Result<()> {
        for (f, l, v) in self.iter() {
            let mut dumper =
                hex::Dumper::with_offset(&mut *sink, "", f.offset())
                .rfc_mode();
            if *l == "body" {
                dumper.write_ascii(f.as_bytes())?;
            } else if v.is_empty() {
                dumper.write(f.as_bytes(), format!("({})", l))?;
            } else {
                dumper.write(f.as_bytes(), format!("{}: {}", l, v))?;
            }
        }

        Ok(())
    }
}

impl<'m> Packet<'m> {
    pub fn dump(&self) -> openpgp::Result<Fields<'m>> {
        let mut fields = Fields {
            f: self.map().iter().map(|f| {
                let name = f.name().into();
                (f.offset(), (f, name, "".into()))
            }).collect(),
        };

        self.header().dump(&mut fields)?;

        match self {
            Packet::Signature(p) => p.dump(&mut fields)?,
            Packet::Literal(p) => p.dump(&mut fields)?,
            _ => (),
        };

        Ok(fields)
    }
}
