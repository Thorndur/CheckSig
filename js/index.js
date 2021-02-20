import getSignatureParts from './signature'
import("../pkg").then(module =>{
    var file = document.getElementById( "file" );
    var output = document.getElementById( "output" );

    file.addEventListener( "change", function( event ) {
        output.innerText = "calculating";
        var fileData = new Blob([event.target.files[0]]);
        fileData.arrayBuffer().then(function (result) {

            let signature_valid = module.check_document(new Uint8Array(result));

            output.innerText = `signature is ${signature_valid ? '': 'not '}valid`;
        });
    });
})
    .catch(console.error);