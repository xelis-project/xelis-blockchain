use octet::DecodeError as OctetDecodeError;
use crate::serializer::{
    DecodeError,
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    ReaderExt,
    Serializer,
    Writable,
    Writer,
    WriterExt,
};
use crate::crypto::{Hash, HASH_SIZE};
use std::{
    borrow::Cow,
    collections::{
        BTreeSet,
        HashMap,
        HashSet
    },
    hash::Hash as StdHash,
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr
    },
    sync::Arc
};
use indexmap::{IndexMap, IndexSet};
use log::{error, warn};

// Used for Tips storage
impl Serializer for HashSet<Hash> {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            for hash in self {
                writer.write_hash(hash)?;
            }
            Ok(())
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let bytes = reader.read_all_bytes()?;
            let total_size = bytes.len();
            let reader = &mut Reader::new(bytes.as_slice());
            if total_size % HASH_SIZE != 0 {
                error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
                return Err(SerializationError::new(DecodeError::InvalidSize))
            }

            let count = total_size / HASH_SIZE;
            let mut tips = HashSet::with_capacity(count);
            for _ in 0..count {
                let hash = reader.read_hash()?;
                tips.insert(hash);
            }

            if tips.len() != count {
                error!("Invalid size: received {} elements while sending {}", tips.len(), count);
                return Err(SerializationError::new(DecodeError::InvalidSize)) 
            }

            Ok(tips)
        })
    }

    fn size(&self) -> usize {
        self.len() * HASH_SIZE
    }
}

// Used for Tips storage
impl Serializer for HashSet<Cow<'_, Hash>> {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            for hash in self {
                writer.write_hash(hash)?;
            }
            Ok(())
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let bytes = reader.read_all_bytes()?;
            let total_size = bytes.len();
            let reader = &mut Reader::new(bytes.as_slice());
            if total_size % 32 != 0 {
                error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
                return Err(SerializationError::new(DecodeError::InvalidSize))
            }

            let count = total_size / 32;
            let mut tips = HashSet::with_capacity(count);
            for _ in 0..count {
                let hash = reader.read_hash()?;
                tips.insert(Cow::Owned(hash));
            }

            if tips.len() != count {
                error!("Invalid size: received {} elements while sending {}", tips.len(), count);
                return Err(SerializationError::new(DecodeError::InvalidSize)) 
            }

            Ok(tips)
        })
    }

    fn size(&self) -> usize {
        self.len() * HASH_SIZE
    }
}

// Implement Serializer for all unsigned numbers

impl Serializer for u128 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_u128(*self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(reader.read_u128()?)
        })
    }

    fn size(&self) -> usize {
        // u128::BITS as usize / 8
        16
    }
}

impl Serializer for u64 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_u64(*self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(reader.read_u64()?)
        })
    }

    fn size(&self) -> usize {
        // u64::BITS as usize / 8
        8
    }
}

impl Serializer for u32 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_u32(*self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(reader.read_u32()?)
        })
    }

    fn size(&self) -> usize {
        // u32::BITS as usize / 8
        4
    }
}

impl Serializer for u16 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_u16(*self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(reader.read_u16()?)
        })
    }

    fn size(&self) -> usize {
        // u16::BITS as usize / 8
        2
    }
}

// Implement Serializer for u8
impl Serializer for u8 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_u8(*self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(reader.read_u8()?)
        })
    }

    fn size(&self) -> usize {
        // u8 is a single byte
        1
    }
}

pub const DEFAULT_MAX_ITEMS: usize = 1024;

impl<T: Serializer + std::hash::Hash + Ord> Serializer for BTreeSet<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let count = reader.read_u16()?;
            if count > DEFAULT_MAX_ITEMS as u16 {
                warn!("Received {} in BTreeSet while maximum is set to {}", count, DEFAULT_MAX_ITEMS);
                return Err(SerializationError::new(DecodeError::InvalidSize))
            }

            let mut set = BTreeSet::new();
            for _ in 0..count {
                let value = T::read(reader)?;
                if !set.insert(value) {
                    error!("Value is duplicated in BTreeSet");
                    return Err(SerializationError::new(DecodeError::InvalidSize))
                }
            }
            Ok(set)
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_u16(self.len() as u16)?;
            for el in self {
                el.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        match self.first() {
            Some(first) => 2 + self.len() * first.size(),
            // If the set is empty, we still need to write the size (u16)
            None => 2
        }
    }
}

impl<T: Serializer + std::hash::Hash + Eq> Serializer for IndexSet<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let count = reader.read_u16()?;
            if count > DEFAULT_MAX_ITEMS as u16 {
                warn!("Received {} in IndexSet while maximum is set to {}", count, DEFAULT_MAX_ITEMS);
                return Err(SerializationError::new(DecodeError::InvalidSize))
            }

            let mut set = IndexSet::new();
            for _ in 0..count {
                let value = T::read(reader)?;
                if !set.insert(value) {
                    error!("Value is duplicated in IndexSet");
                    return Err(SerializationError::new(DecodeError::InvalidSize))
                }
            }
            Ok(set)
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_u16(self.len() as u16)?;
            for el in self {
                el.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        match self.first() {
            Some(first) => 2 + self.len() * first.size(),
            // If the set is empty, we still need to write the size (u16)
            None => 2
        }
    }
}

impl<T: Serializer + Clone> Serializer for Cow<'_, T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Cow::Owned(T::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| self.as_ref().write(writer))
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

impl Serializer for Cow<'_, str> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Cow::Owned(reader.read_string()?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_string(self))
    }

    fn size(&self) -> usize {
        self.len() + 1
    }
}

impl<T: Serializer> Serializer for Option<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            if reader.read_bool()? {
                Ok(Some(T::read(reader)?))
            } else {
                Ok(None)
            }
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_bool(self.is_some())?;
            if let Some(value) = self {
                value.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        // 1 is for the bool written as a full byte
        match self {
            Some(value) => 1 + value.size(),
            None => 1
        }
    }
}

impl<T: Serializer> Serializer for Vec<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let count = reader.read_u16()?;
            if count > DEFAULT_MAX_ITEMS as u16 {
                warn!("Received {} in Vec while maximum is set to {}", count, DEFAULT_MAX_ITEMS);
                return Err(SerializationError::new(DecodeError::InvalidSize))
            }

            let mut values = Vec::with_capacity(count as usize);
            for _ in 0..count {
                values.push(T::read(reader)?);
            }

            Ok(values)
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_u16(self.len() as u16)?;
            for el in self {
                el.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        2 + self.iter().map(|el| el.size()).sum::<usize>()
    }
}

impl Serializer for String {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            reader.read_string()
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_string(self))
    }

    fn size(&self) -> usize {
        // 1 for str len as byte + str len
        1 + self.as_bytes().len().min(u8::MAX as usize)
    }
}

impl Serializer for bool {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            reader.read_bool()
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_bool(*self))
    }

    fn size(&self) -> usize {
        // 1 for bool as byte
        1
    }
}

// Supports up to 2^16 elements
impl<K: Serializer + Eq + StdHash, V: Serializer + Eq + StdHash> Serializer for HashMap<K, V> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let size = reader.read_u16()?;
            let mut map = HashMap::with_capacity(size as usize);
            for _ in 0..size {
                let k = K::read(reader)?;
                let v = V::read(reader)?;
                map.insert(k, v);
            }

            Ok(map)
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_u16(self.len() as u16)?;
            for (key, value) in self.iter() {
                key.write(writer)?;
                value.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        // 2 for the size of the map (u16)
        let mut size = 2;
        for (key, value) in self.iter() {
            size += key.size() + value.size();
        }
        size
    }
}

impl<const N: usize> Serializer for [u8; N] {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_bytes(self))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let mut bytes = [0; N];
            reader.read_exact(&mut bytes)?;
            Ok(bytes)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        Ok(self.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderError>
        where Self: Sized {
        if bytes.len() != N {
            return Err(SerializationError::new(DecodeError::InvalidSize))
        }

        let mut array = [0; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn size(&self) -> usize {
        N
    }
}

impl Serializer for SocketAddr {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let ip = IpAddr::read(reader)?;
            let port = reader.read_u16()?;
            Ok(SocketAddr::new(ip, port))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.ip().write(writer)?;
            self.port().write(writer)
        })
    }

    fn size(&self) -> usize {
        // 1 for the ip version
        // 4 for ipv4 and 16 for ipv6
        // 2 for the port (u16)
        match self.ip() {
            IpAddr::V4(_) => 1 + 4 + 2,
            IpAddr::V6(_) => 1 + 16 + 2
        }
    }
}

impl Serializer for IpAddr {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            match reader.read_u8()? {
                0 => {
                    let a = reader.read_u8()?;
                    let b = reader.read_u8()?;
                    let c = reader.read_u8()?;
                    let d = reader.read_u8()?;
                    Ok(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
                },
                1 => {
                    let a = reader.read_u16()?;
                    let b = reader.read_u16()?;
                    let c = reader.read_u16()?;
                    let d = reader.read_u16()?;
                    let e = reader.read_u16()?;
                    let f = reader.read_u16()?;
                    let g = reader.read_u16()?;
                    let h = reader.read_u16()?;
                    Ok(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)))
                },
                _ => Err(SerializationError::new(DecodeError::InvalidValue))
            }
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                IpAddr::V4(addr) => {
                    writer.write_u8(0)?;
                    writer.write_bytes(&addr.octets())
                },
                IpAddr::V6(addr) => {
                    writer.write_u8(1)?;
                    writer.write_bytes(&addr.octets())
                }
            }
        })
    }

    fn size(&self) -> usize {
        match self {
            IpAddr::V4(_) => 1 + 4,
            IpAddr::V6(_) => 1 + 16
        }
    }
}

impl Serializer for () {
    fn read<'ty, 'r, R: Readable>(_reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        Ok(())
    }

    fn write<'ty, 'r, W: Writable>(&self, _writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        Ok(())
    }

    fn size(&self) -> usize {
        0
    }
}

impl<L: Serializer, Right: Serializer> Serializer for (L, Right) {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok((L::read(reader)?, Right::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.0.write(writer)?;
            self.1.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.0.size() + self.1.size()
    }
}

impl<A: Serializer, B: Serializer, C: Serializer> Serializer for (A, B, C) {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok((A::read(reader)?, B::read(reader)?, C::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.0.write(writer)?;
            self.1.write(writer)?;
            self.2.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.0.size() + self.1.size() + self.2.size()
    }
}

impl<A: Serializer, B: Serializer, C: Serializer, D: Serializer> Serializer for (A, B, C, D) {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok((A::read(reader)?, B::read(reader)?, C::read(reader)?, D::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.0.write(writer)?;
            self.1.write(writer)?;
            self.2.write(writer)?;
            self.3.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.0.size() + self.1.size() + self.2.size() + self.3.size()
    }
}

impl<K: Serializer + std::hash::Hash + Eq, V: Serializer> Serializer for IndexMap<K, V> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let size = reader.read_u16()?;
            let mut map = IndexMap::with_capacity(size as usize);
            for _ in 0..size {
                let k = K::read(reader)?;
                let v = V::read(reader)?;
                map.insert(k, v);
            }

            Ok(map)
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            writer.write_u16(self.len() as u16)?;
            for (key, value) in self.iter() {
                key.write(writer)?;
                value.write(writer)?;
            }
            Ok(())
        })
    }

    fn size(&self) -> usize {
        // 2 for the size of the map (u16)
        let mut size = 2;
        for (key, value) in self.iter() {
            size += key.size() + value.size();
        }
        size
    }
}

impl<T: Serializer> Serializer for Box<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Box::new(T::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| self.as_ref().write(writer))
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

impl<T: Serializer> Serializer for Arc<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Arc::new(T::read(reader)?))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| self.as_ref().write(writer))
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

impl<'a> Serializer for &'a [u8] {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.write_bytes(self))
    }

    fn read<'ty, 'r, R: Readable>(_: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        Err(OctetDecodeError::NotImplemented.into())
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a, T: Serializer> Serializer for &'a T {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| (*self).write(writer))
    }

    fn read<'ty, 'r, R: Readable>(_: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        Err(OctetDecodeError::NotImplemented.into())
    }

    fn size(&self) -> usize {
        (*self).size()
    }
}
