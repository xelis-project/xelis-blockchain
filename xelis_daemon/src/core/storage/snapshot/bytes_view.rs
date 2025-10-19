use std::{borrow::Cow, ops::Deref};

use bytes::Bytes;

/// A view over different byte storage types to provide a unified interface
/// for accessing byte data.
pub enum BytesView<'a> {
    Bytes(Cow<'a, Bytes>),
    #[cfg(feature = "sled")]
    IVec(sled::IVec),
    Boxed(Box<[u8]>),
    Ref(&'a [u8]),
}

impl <'a> AsRef<[u8]> for BytesView<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            BytesView::Bytes(b) => b.as_ref(),
            #[cfg(feature = "sled")]
            BytesView::IVec(ivec) => ivec.as_ref(),
            BytesView::Boxed(b) => b.as_ref(),
            BytesView::Ref(r) => r,
        }
    }
}

impl Deref for BytesView<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl From<Bytes> for BytesView<'_> {
    fn from(bytes: Bytes) -> Self {
        BytesView::Bytes(Cow::Owned(bytes))
    }
}

impl<'a> From<&'a [u8]> for BytesView<'a> {
    fn from(slice: &'a [u8]) -> Self {
        BytesView::Ref(slice)
    }
}

impl<'a> From<Cow<'a, Bytes>> for BytesView<'a> {
    fn from(cow: Cow<'a, Bytes>) -> Self {
        BytesView::Bytes(cow)
    }
}

impl<'a> From<&'a Bytes> for BytesView<'a> {
    fn from(bytes: &'a Bytes) -> Self {
        BytesView::Bytes(Cow::Borrowed(bytes))
    }
}
impl From<Box<[u8]>> for BytesView<'_> {
    fn from(boxed: Box<[u8]>) -> Self {
        BytesView::Boxed(boxed)
    }
}

impl From<Vec<u8>> for BytesView<'_> {
    fn from(vec: Vec<u8>) -> Self {
        BytesView::Boxed(vec.into_boxed_slice())
    }
}

#[cfg(feature = "sled")]
impl From<sled::IVec> for BytesView<'_> {
    fn from(ivec: sled::IVec) -> Self {
        BytesView::IVec(ivec)
    }
}