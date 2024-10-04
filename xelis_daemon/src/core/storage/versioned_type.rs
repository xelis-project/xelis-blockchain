use std::borrow::Cow;

use xelis_common::{
    block::TopoHeight,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

// A versioned by topoheight data
pub struct Versioned<'a, T: Serializer + Clone> {
    data: Cow<'a, T>,
    previous_topoheight: Option<u64>,
}

impl<'a, T: Serializer + Clone> Versioned<'a, T> {
    pub fn new(data: Cow<'a, T>, previous_topoheight: Option<u64>) -> Self {
        Self {
            data,
            previous_topoheight,
        }
    }

    pub fn get(&self) -> &T {
        &self.data
    }

    pub fn set(&mut self, data: Cow<'a, T>) {
        self.data = data;
    }

    pub fn get_previous_topoheight(&self) -> Option<TopoHeight> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<TopoHeight>) {
        self.previous_topoheight = previous_topoheight;
    }

    pub fn take(self) -> Cow<'a, T> {
        self.data
    }
}

impl<'a, T: Serializer + Clone> Serializer for Versioned<'a, T> {
    fn write(&self, writer: &mut Writer) {
        self.data.write(writer);
        if let Some(topo) = &self.previous_topoheight {
            topo.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let data = Cow::Owned(T::read(reader)?);
        let previous_topoheight = if reader.size() == 0 {
            None
        } else {
            Some(Reader::read(reader)?)
        };

        Ok(Self {
            data,
            previous_topoheight
        })
    }

    fn size(&self) -> usize {
        self.data.size() + if let Some(topoheight) = self.previous_topoheight { topoheight.size() } else { 0 }
    }
}