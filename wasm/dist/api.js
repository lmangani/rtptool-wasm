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
      extract: Module.cwrap('extract_pcap', 'string', ['string', 'string']),
    };
    console.log(api.version());


    // ANALYZE PCAP
    var filename = '/tmp/rtp.pcap';
    // Browser
    if(typeof FileReader !== 'undefined'){
    	var reader = new FileReader();
        reader.readAsArrayBuffer(filename);
        reader.onload = (function(){
		console.log("File reading finished, passing data to WASM", filename);
		var raw_data = new Uint8Array(reader.result, 0, reader.result.byteLength);
		Module.FS.writeFile('tmp.pcap', raw_data);
		var contents = Module.FS.readFile('tmp.pcap');
		console.log(api.analyze('tmp.pcap'));
		var json = Module.FS.readFile('report.json', {encoding: 'utf8'});
		console.log(JSON.parse(json));
        });
    // Node
    } else {
	var reader = require('fs');
        var raw_data = reader.readFileSync(filename);
		Module.FS.writeFile('tmp.pcap', raw_data);
		var contents = Module.FS.readFile('tmp.pcap');
		console.log(api.analyze('tmp.pcap'));
		var json = Module.FS.readFile('report.json', {encoding: 'utf8'});
		json = JSON.parse(json);
		console.log(json);
    }


    // EXTRACT RAW PAYLOAD
    // d2bd4e3e
    var filename = '/tmp/rtp.pcap';
    var ssrc = '0xd2bd4e3e';
    // Browser
    if(typeof FileReader !== 'undefined'){
    	var reader = new FileReader();
        reader.readAsArrayBuffer(filename);
        reader.onload = (function(){
		console.log("File reading finished, passing data to WASM", filename);
		var raw_data = new Uint8Array(reader.result, 0, reader.result.byteLength);
		Module.FS.writeFile('tmp.pcap', raw_data);
		console.log(api.extract(ssrc, 'tmp.pcap'));
		var content = Module.FS.readFile(filename+'.wav');
		const wavUrl = URL.createObjectURL(
		    new Blob(
		      [new Uint8Array(content, content.byteOffset, content.length)],
		      { type: "audio/wav" }
		    )
		  );
		console.log('wav', wavUrl);
        });
    // Node
    } else {
	var reader = require('fs');
        var raw_data = reader.readFileSync(filename);
		Module.FS.writeFile('tmp.pcap', raw_data);
		console.log(api.extract(ssrc, 'tmp.pcap'));
		var content = Module.FS.readFile(ssrc+'.wav');
		console.log('wav', content);
    }


  };

