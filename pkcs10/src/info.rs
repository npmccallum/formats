use crate::{Attributes, Version};
use der::{asn1, Decodable, Decoder, Encodable, Sequence, Tag, TagMode, TagNumber};

/// PKCS#10 `CertificationRequestInfo` as defined in [RFC 2986 Section 4].
///
/// ```text
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) } (v1,...),
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///     attributes    [0] Attributes{{ CRIAttributes }}
/// }
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertReqInfo<'a> {
    /// Certification request version.
    pub version: Version,

    /// Subject name.
    pub subject: x509::Name<'a>,

    /// Subject public key info.
    pub public_key: spki::SubjectPublicKeyInfo<'a>,

    /// Request attributes.
    pub attributes: Attributes<'a>,
}

impl<'a> Decodable<'a> for CertReqInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let version = decoder.decode()?;
            let subject = decoder.decode()?;
            let public_key = decoder.decode()?;
            let attributes = asn1::ContextSpecific::decode_implicit(decoder, TagNumber::N0)?
                .ok_or_else(|| {
                    Tag::ContextSpecific {
                        number: TagNumber::N0,
                        constructed: false,
                    }
                    .value_error()
                })?
                .value;
            Ok(Self {
                version,
                subject,
                public_key,
                attributes,
            })
        })
    }
}

impl<'a> Sequence<'a> for CertReqInfo<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        f(&[
            &self.version,
            &self.subject,
            &self.public_key,
            &asn1::ContextSpecific {
                tag_number: TagNumber::new(0),
                tag_mode: TagMode::Implicit,
                value: self.attributes.clone(),
            },
        ])
    }
}

impl<'a> TryFrom<&'a [u8]> for CertReqInfo<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}
