use crate::crypto::{Hash, HASH_SIZE};
use super::{Serializer, Writer, Reader, ReaderError};
use std::{
    collections::{HashSet, BTreeSet, HashMap},
    borrow::Cow,
    hash::Hash as StdHash,
    net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr
    }
};
use indexmap::{IndexMap, IndexSet};
use log::{error, warn};

// Used for Tips storage
impl Serializer for HashSet<Hash> {
    fn write(&self, writer: &mut Writer) {
        for hash in self {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % 32 != 0 {
            error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size / 32;
        let mut tips = HashSet::with_capacity(count);
        for _ in 0..count {
            let hash = reader.read_hash()?;
            tips.insert(hash);
        }

        if tips.len() != count {
            error!("Invalid size: received {} elements while sending {}", tips.len(), count);
            return Err(ReaderError::InvalidSize) 
        }

        Ok(tips)
    }

    fn size(&self) -> usize {
        self.len() * HASH_SIZE
    }
}

// Used for Tips storage
impl Serializer for HashSet<Cow<'_, Hash>> {
    fn write(&self, writer: &mut Writer) {
        for hash in self {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % 32 != 0 {
            error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size / 32;
        let mut tips = HashSet::with_capacity(count);
        for _ in 0..count {
            let hash = reader.read_hash()?;
            tips.insert(Cow::Owned(hash));
        }

        if tips.len() != count {
            error!("Invalid size: received {} elements while sending {}", tips.len(), count);
            return Err(ReaderError::InvalidSize) 
        }

        Ok(tips)
    }

    fn size(&self) -> usize {
        self.len() * HASH_SIZE
    }
}

// Implement Serializer for all unsigned numbers

impl Serializer for u128 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u128(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u128()?)
    }

    fn size(&self) -> usize {
        // u128::BITS as usize / 8
        16
    }
}

impl Serializer for u64 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u64()?)
    }

    fn size(&self) -> usize {
        // u64::BITS as usize / 8
        8
    }
}

impl Serializer for u32 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u32(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u32()?)
    }

    fn size(&self) -> usize {
        // u32::BITS as usize / 8
        4
    }
}

impl Serializer for u16 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u16(*self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u16()?)
    }

    fn size(&self) -> usize {
        // u16::BITS as usize / 8
        2
    }
}

// Implement Serializer for u8
impl Serializer for u8 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(*self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u8()?)
    }

    fn size(&self) -> usize {
        // u8 is a single byte
        1
    }
}

const MAX_ITEMS: usize = 1024;

impl<T: Serializer + std::hash::Hash + Ord> Serializer for BTreeSet<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut set = BTreeSet::new();
        for _ in 0..count {
            let value = T::read(reader)?;
            if !set.insert(value) {
                error!("Value is duplicated in BTreeSet");
                return Err(ReaderError::InvalidSize)
            }
        }
        Ok(set)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut set = IndexSet::new();
        for _ in 0..count {
            let value = T::read(reader)?;
            if !set.insert(value) {
                error!("Value is duplicated in IndexSet");
                return Err(ReaderError::InvalidSize)
            }
        }
        Ok(set)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Cow::Owned(T::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.as_ref().write(writer);
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

impl<T: Serializer> Serializer for Option<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        if reader.read_bool()? {
            Ok(Some(T::read(reader)?))
        } else {
            Ok(None)
        }
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_bool(self.is_some());
        if let Some(value) = self {
            value.write(writer);
        }
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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut values = Vec::with_capacity(count as usize);
        for _ in 0..count {
            values.push(T::read(reader)?);
        }

        Ok(values)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
    }

    fn size(&self) -> usize {
        match self.first() {
            Some(first) => 2 + self.len() * first.size(),
            // If the vector is empty, we still need to write the size (u16)
            None => 2
        }
    }
}

impl Serializer for String {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        reader.read_string()
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_string(self);
    }

    fn size(&self) -> usize {
        // 1 for str len as byte + str len
        1 + self.len()
    }
}

impl Serializer for bool {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        reader.read_bool()
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_bool(*self);
    }

    fn size(&self) -> usize {
        // 1 for bool as byte
        1
    }
}


// Supports up to 2^16 elements
impl<K: Serializer + Eq + StdHash, V: Serializer + Eq + StdHash> Serializer for HashMap<K, V> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let size = reader.read_u16()?;
        let mut map = HashMap::with_capacity(size as usize);
        for _ in 0..size {
            let k = K::read(reader)?;
            let v = V::read(reader)?;
            map.insert(k, v);
        }

        Ok(map)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for (key, value) in self.iter() {
            key.write(writer);
            value.write(writer);
        }
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
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bytes = reader.read_bytes(N)?;
        Ok(
            bytes
        )
    }

    fn size(&self) -> usize {
        N
    }
}

impl Serializer for SocketAddr {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let is_v6 = reader.read_bool()?;
        let ip: IpAddr = if !is_v6 {
            let a = reader.read_u8()?;
            let b = reader.read_u8()?;
            let c = reader.read_u8()?;
            let d = reader.read_u8()?;
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        } else {
            let a = reader.read_u16()?;
            let b = reader.read_u16()?;
            let c = reader.read_u16()?;
            let d = reader.read_u16()?;
            let e = reader.read_u16()?;
            let f = reader.read_u16()?;
            let g = reader.read_u16()?;
            let h = reader.read_u16()?;
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        };
        let port = reader.read_u16()?;
        Ok(SocketAddr::new(ip, port))
    }

    fn write(&self, writer: &mut Writer) {
        match self.ip() {
            IpAddr::V4(addr) => {
                writer.write_u8(0);
                writer.write_bytes(&addr.octets());
            },
            IpAddr::V6(addr) => {
                writer.write_u8(1);
                writer.write_bytes(&addr.octets());
            }
        };
        self.port().write(writer);
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

impl Serializer for () {
    fn read(_reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(())
    }

    fn write(&self, _writer: &mut Writer) {
    }

    fn size(&self) -> usize {
        0
    }
}

impl<L: Serializer, R: Serializer> Serializer for (L, R) {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok((L::read(reader)?, R::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
        self.1.write(writer);
    }

    fn size(&self) -> usize {
        self.0.size() + self.1.size()
    }
}

impl<A: Serializer, B: Serializer, C: Serializer> Serializer for (A, B, C) {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok((A::read(reader)?, B::read(reader)?, C::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
        self.1.write(writer);
        self.2.write(writer);
    }

    fn size(&self) -> usize {
        self.0.size() + self.1.size() + self.2.size()
    }
}

impl<K: Serializer + std::hash::Hash + Eq, V: Serializer> Serializer for IndexMap<K, V> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let size = reader.read_u16()?;
        let mut map = IndexMap::with_capacity(size as usize);
        for _ in 0..size {
            let k = K::read(reader)?;
            let v = V::read(reader)?;
            map.insert(k, v);
        }

        Ok(map)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for (key, value) in self.iter() {
            key.write(writer);
            value.write(writer);
        }
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