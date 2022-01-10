use der::asn1::{Any, ObjectIdentifier, SetOfVec};
use der::{Decodable, OrdIsValueOrd, Sequence};

/// PKCS#10 `Attribute` as defined in [RFC 2986 Section 4].
///
/// ```text
/// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///     type   ATTRIBUTE.&id({IOSet}),
///     values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
/// }
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Sequence)]
pub struct Attribute<'a> {
    /// Attribute kind (OID).
    pub oid: ObjectIdentifier,

    /// Attribute values.
    pub values: SetOfVec<Any<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for Attribute<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}

impl<'a> OrdIsValueOrd for Attribute<'a> {}

/// PKCS#10 `Attributes` as defined in [RFC 2986 Section 4].
///
/// ```text
/// Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
pub type Attributes<'a> = SetOfVec<Attribute<'a>>;
