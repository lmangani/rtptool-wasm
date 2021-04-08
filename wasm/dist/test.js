/*
<script src="./rtptool.js"></script>
<script>
  Module.onRuntimeInitialized = async _ => {
    const api = {
      version: Module.cwrap('version', 'number', []),
    };
    console.log(api.version());
  };
</script>
*/

require("./rtptool.js");
    const api = {
      version: Module.cwrap('version', 'number', []),
    };
    console.log(api.version());
