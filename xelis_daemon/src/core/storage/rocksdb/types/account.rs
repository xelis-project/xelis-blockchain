use xelis_common::{
    block::TopoHeight,
    serializer::{Error as SerializationError, *},
};

pub type AccountId = u64;

pub struct Account {
    // id used to prevent duplicated raw key
    // and save some space
    pub id: AccountId,
    // At which topoheight the account has been seen
    // for the first time
    pub registered_at: Option<TopoHeight>,
    // pointer to the last versioned nonce
    pub nonce_pointer: Option<TopoHeight>,
    // pointer to the last versioned multisig
    pub multisig_pointer: Option<TopoHeight>,
}

impl Serializer for Account {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let id = AccountId::read(reader)?;
            let registered_at = Option::read(reader)?;
            let nonce_pointer = Option::read(reader)?;
            let multisig_pointer = Option::read(reader)?;

            Ok(Self {
                id,
                registered_at,
                nonce_pointer,
                multisig_pointer
            })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.id.write(writer)?;
            self.registered_at.write(writer)?;
            self.nonce_pointer.write(writer)?;
            self.multisig_pointer.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.id.size()
        + self.registered_at.size()
        + self.nonce_pointer.size()
        + self.multisig_pointer.size()
    }
}