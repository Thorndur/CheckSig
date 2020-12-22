import("../pkg").then(module =>{
    var file = document.getElementById( "file" );
    var output = document.getElementById( "output" );

    file.addEventListener( "change", function( event ) {
        output.innerText = "calculating";
        var fileData = new Blob([event.target.files[0]]);
        fileData.arrayBuffer().then(function (result) {

            const asn1js = require("asn1js");
            const pkijs = require("pkijs");

            const Signature = pkijs.SignedData;


            let signatureArray = module.get_signature_from_file(result);

            // const fromHexString = hexString => new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            //
            //
            // const buffer = fromHexString(signedDataString).buffer;

            const asn1 = asn1js.fromBER(signatureArray.buffer);
            let SigObject = new Signature({ schema: asn1.result });

            let signedAttributes = new Uint8Array(SigObject.signerInfos[0].signedAttrs.encodedValue);
            let signedHash = new Uint8Array(SigObject.signerInfos[0].signature.valueBlock.valueHex);
            let publicKey = new Uint8Array(SigObject.certificates[0].subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);

            //signature = Array.prototype.map.call(new Uint8Array(signature), x => ('00' + x.toString(16)).slice(-2)).join('');

            module.check_signature(signedHash, publicKey);
        });
    });
})
    .catch(console.error);