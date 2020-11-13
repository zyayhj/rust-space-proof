

#[derive(Clone)]
pub struct Digest {
    pub value: Vec<u8>,
    pub algorithm: &'static Algorithm,
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl AsRef<[u8]> for Digest {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:?}:{:?}", self.algorithm, self.value)
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:?}:{:?}", self.algorithm,self.value)
    }
}


/// A digest algorithm.
pub struct Algorithm {
}

impl core::fmt::Debug for Algorithm{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "")
    }
}

impl Algorithm {
    
}
