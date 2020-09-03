use picky_asn1_der::{Asn1RawDer};
use picky_asn1::wrapper::{Asn1SetOf, ApplicationTag0, ApplicationTag1, Implicit, ObjectIdentifierAsn1};
use serde_derive::{ Serialize, Deserialize };


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct PDFSignature {
    pub object_identifier: ObjectIdentifierAsn1,
    //pub signed_data: Asn1RawDer,
    pub signed_data: Option<ApplicationTag0<SignedData>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IgnoreImplicitSet(Asn1SetOf<Asn1RawDer>);

impl Default for IgnoreImplicitSet {
    fn default() -> Self {
        Self(
            Asn1SetOf::from(vec![Asn1RawDer(vec![0x30, 0x08, 0x0C, 0x03, 0x41, 0x62, 0x63, 0x02, 0x01, 0x05])])
        )
    }
}

fn implicit_field_is_default(wrapper: &Implicit<IgnoreImplicitSet>) -> bool {
    wrapper.0 == IgnoreImplicitSet::default()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct SignedData {
    pub version: u8,
    pub digest_algorithms: Asn1RawDer,
    pub encap_content_info: Asn1RawDer,
    pub certificates: Implicit<Option<ApplicationTag0<Asn1RawDer>>>,
    pub crls: Implicit<Option<ApplicationTag1<Asn1RawDer>>>,
    //pub signer_infos: Asn1RawDer,
    pub signer_infos: Asn1SetOf<SignerInfo>,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct SignerInfo {
    pub version: u8,
    pub sid: Asn1RawDer,
    pub digest_algorithm: Asn1RawDer,
    #[serde(skip_serializing_if = "implicit_field_is_default")]
    pub signed_attrs: ApplicationTag0<Implicit<IgnoreImplicitSet>>,
    //pub signed_attrs: Asn1RawDer,
    pub signature_algorithm: Asn1RawDer,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    //pub unsigned_attrs: Implicit<IgnoreImplicitTag>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct SignedAttr{
    pub object_identifier: ObjectIdentifierAsn1,
    pub signed_data: Asn1SetOf<Asn1RawDer>,
}



