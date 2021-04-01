export function getSignatureParts(signatureArray) {
    const asn1js = require("asn1js");
    const pkijs = require("pkijs");

    const Signature = pkijs.SignedData;

    const asn1 = asn1js.fromBER(signatureArray.buffer);
    let SigObject = new Signature({ schema: asn1.result });

    let signedAttributes = new Uint8Array(SigObject.signerInfos[0].signedAttrs.encodedValue);
    let hashAlgorithmId = SigObject.digestAlgorithms[0].algorithmId;
    let messageHash = new Uint8Array(SigObject.signerInfos[0].signedAttrs.attributes
        .find(attribute => attribute.type === "1.2.840.113549.1.9.4").values[0].valueBlock.valueHex);
    let signatureAlgorithmId = SigObject.signerInfos[0].signatureAlgorithm.algorithmId;
    let signedHash = new Uint8Array(SigObject.signerInfos[0].signature.valueBlock.valueHex);
    let certificates = SigObject.certificates.map(certificate => new Uint8Array(certificate.toSchema().toBER()));

    return {
        signed_attributes_buffer: signedAttributes,
        hash_algorithm_id: hashAlgorithmId,
        message_hash_buffer: messageHash,
        signature_algorithm_id: signatureAlgorithmId,
        signature_buffer: signedHash,
        certificates_buffer: certificates
    };
}