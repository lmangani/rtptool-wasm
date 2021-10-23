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
    console.log(api.analyze('rtp.pcap'));
  };

