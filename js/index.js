import("../pkg/index.js").then(module =>{
    var file = document.getElementById( "file" );
    var output = document.getElementById( "output" );

    file.addEventListener( "change", function( event ) {
        output.innerText = "calculating";
        var fileData = new Blob([event.target.files[0]]);
        fileData.arrayBuffer().then(function (result) {
            output.innerText = module.check_file(result);
        });
    });
})
    .catch(console.error);
