/*
<script src="./rtptool.js"></script>
<script>
</script>
*/

const Module = require("./rtptool.js");

  Module.onRuntimeInitialized = async _ => {
    const api = {
      version: Module.cwrap('version', 'string', []),
      analyze: Module.cwrap('analyze_pcap', 'string', ['string']),
    };
    console.log(api.version());
    //let stream = FS.open(filename, 'w+');
    //FS.write(stream, data, 0, data.length, 0);
    //FS.close(stream);
    //console.log(Module.FS);
    var filename = '/tmp/rtp.pcap';
    if(typeof FileReader !== 'undefined'){
    	var reader = new FileReader();
        reader.readAsArrayBuffer(filename);
        reader.onload = (function(){
		console.log("File reading finished, passing data to WASM", filename);
		var raw_data = new Uint8Array(reader.result, 0, reader.result.byteLength);
		Module.FS.writeFile('tmp.pcap', raw_data);
		var contents = Module.FS.readFile('tmp.pcap');
		console.log(api.analyze('tmp.pcap'));
        });
    } else {
	var reader = require('fs');
        var raw_data = reader.readFileSync(filename);
		Module.FS.writeFile('tmp.pcap', raw_data);
		var contents = Module.FS.readFile('tmp.pcap');
		console.log(api.analyze('tmp.pcap'));
    }

  };

