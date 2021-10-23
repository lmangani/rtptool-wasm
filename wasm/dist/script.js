onst message = document.getElementById("message");

var rtptool, api;

const load_pcap = async ({ target: { files } }) => {
  try {
    const { name } = files[0];
    message.innerHTML = "Loading PCAP...";

    // File method
    if (typeof FileReader !== "undefined") {
      var reader = new FileReader();
      reader.readAsArrayBuffer(files[0]);
      reader.onload = function() {
        console.log("File reading finished, passing data to WASM", name);
        var raw_data = new Uint8Array(
          reader.result,
          0,
          reader.result.byteLength
        );
        rtptool.FS.writeFile("tmp.pcap", raw_data);
        var contents = rtptool.FS.readFile("tmp.pcap");
        console.log(api.analyze("tmp.pcap"));
        var report = JSON.parse(
          rtptool.FS.readFile("report.json", { encoding: "utf8" })
        );
        console.log("RTP LEGS", report);
        var ssrcs = document.getElementById("ssrcs");
        ssrcs.innerHTML =
          '<option value="" selected="selected">Select a Stream</option>';
        Object.keys(report).forEach(function(row) {
          var option = document.createElement("option");
          option.text = report[row].ssrc;
          option.value = report[row].ssrc;
          ssrcs.add(option);
        });
        ssrcs.removeAttribute("hidden");
        message.innerHTML = "Choose a Stream";
        document
          .getElementById("ssrcs")
          .addEventListener("change", extract_pcap);
      };
    }
  } catch (e) {
    console.log(e);
  }
};

const extract_pcap = async ({ target: { files } }) => {
  try {
    var selectElement = event.target;
    var ssrc = selectElement.value;
    console.log("!!!!!!!!!", ssrc);
    message.innerHTML = "Extracting " + ssrc;

    // URL method
    try {
      var contents = rtptool.FS.readFile("tmp.pcap");
      var e = api.extract(ssrc, "tmp.pcap");
      console.log(e);
      var content = rtptool.FS.readFile(ssrc + ".wav");
      const wavUrl = URL.createObjectURL(
        new Blob(
          [new Uint8Array(content, content.byteOffset, content.length)],
          { type: "audio/wav" }
        )
      );
      console.log("wav", wavUrl, content);
      message.innerHtml = "Completed";
      const audio = document.getElementById("output-audio");
      audio.src = wavUrl;
      message.innerHTML = "Ready";
    } catch (e) {
      console.log(e);
    }
  } catch (e) {
    console.log(e);
  }
};

document.getElementById("pcap").addEventListener("change", load_pcap);

Module.onRuntimeInitialized = () => {
  console.log("RTPTool Module initialized");
  rtptool = Module;
  api = {
    version: rtptool.cwrap("version", "string", []),
    analyze: rtptool.cwrap("analyze_pcap", "string", ["string"]),
    extract: rtptool.cwrap("extract_pcap", "string", ["string", "string"])
  };
  console.log(api.version());
};
