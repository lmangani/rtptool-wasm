/*
<script src="./rtptool.js"></script>
<script>
</script>
*/

const Module = require("./rtptool.js");


// WASM call
function WASM_CONVERT_IMAGE(data, informat, outformat) {
    // data: Uint8Array
    // informat/outformat: 0:JPEG, 1:PNG
    ret = Module.convertImage(data, data.length, informat, outformat);
    return ret;
}

  Module.onRuntimeInitialized = async _ => {
    const api = {
      version: Module.cwrap('version', 'string', []),
    };
    console.log(api.version());
  };
