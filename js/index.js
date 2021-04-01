import("../pkg").then(module => {
    var file = document.getElementById( "file" );
    var output = document.getElementById( "output" );

    file.addEventListener( "change", function( event ) {
        output.innerText = "checking";
        var fileData = new Blob([event.target.files[0]]);
        fileData.arrayBuffer().then(function (result) {
            module.check_document(new Uint8Array(result))
                .then(output.innerText = "signature is valid")
                .catch(error => {
                    output.innerText = "Error: " + error
                });
        });
    });
})
    .catch(console.error);