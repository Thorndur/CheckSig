import getSignatureParts from './signature'
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


            output.innerText = `signature is ${signature_valid ? '': 'not '}valid`;
        });
    });
})
    .catch(console.error);