mod step;
mod types;

use xelis_common::serializer::*;

pub use step::*;
pub use types::*;

#[derive(Debug)]
pub struct BootstrapChainRequest<'a> {
    id: u64,
    step: StepRequest<'a>
}

impl<'a> BootstrapChainRequest<'a> {
    pub fn new(id: u64, step: StepRequest<'a>) -> Self {
        Self {
            id,
            step
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn kind(&self) -> StepKind {
        self.step.kind()
    }

    pub fn step(self) -> StepRequest<'a> {
        self.step
    }
}

impl Serializer for BootstrapChainRequest<'_> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u64()?;
        let step = StepRequest::read(reader)?;
        Ok(Self::new(id, step))
    }

    fn write(&self, writer: &mut Writer) {
        self.id.write(writer);
        self.step.write(writer);
    }

    fn size(&self) -> usize {
        self.id.size() +
        self.step.size()
    }
}


#[derive(Debug)]
pub struct BootstrapChainResponse {
    id: u64,
    response: StepResponse
}

impl BootstrapChainResponse {
    pub fn new(id: u64, response: StepResponse) -> Self {
        Self {
            id,
            response
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn kind(&self) -> StepKind {
        self.response.kind()
    }

    pub fn response(self) -> StepResponse {
        self.response
    }
}

impl Serializer for BootstrapChainResponse {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u64()?;
        let response = StepResponse::read(reader)?;
        Ok(Self::new(id, response))
    }

    fn write(&self, writer: &mut Writer) {
        self.id.write(writer);
        self.response.write(writer);
    }

    fn size(&self) -> usize {
        self.id.size() +
        self.response.size()
    }
}