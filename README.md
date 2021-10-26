```
┬─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┬    ┬ ┬┌─┐┌─┐┌┬┐
├┬┘ │ ├─┘ │ │ ││ ││    │││├─┤└─┐│││
┴└─ ┴ ┴   ┴ └─┘└─┘┴─┘  └┴┘┴ ┴└─┘┴ ┴
```

Extract RTP and Decrypt SRTP Audio streams from .PCAP files in the browser using WASM

### Status
- [x] WASM code is working, but experimental!
- [x] PCAP-> RTP-> SSRC Extraction 
- [x] PCMA/PCMU native decoder
- [ ] Raw decoding with [FFMPEG-WASM](https://github.com/lmangani/ffmpeg-wasm-voip)

### Build Native
###### x86_64
`./build.sh` 

###### WASM using Docker
`./build-wasm-docker.sh`


-------------------
### WASM Module Usage
Check out the included [example](wasm/dist/api.js) for API usage.
```
npm run test
```

In a nutshell:
```javascript
  // Write or fetch binary PCAP data from JS to the virtual FS
  Module.FS.writeFile('tmp.pcap', raw_pcap_data);
  // Analyze the virtual PCAP file in wasm
  Module.api.analyze('tmp.pcap', 'report.json');
  // Read the analysis output back into JS
  Module.FS.readFile('report.json', {encoding: 'utf8'});
```

```
npm run test
```

##### Functions
- [x] analyze_pcap
- [x] extract_pcap
- [x] decrypt_pcap

##### API
```javascript
const api = {
  version: Module.cwrap('version', 'string', []), // null
  analyze: Module.cwrap('analyze_pcap', 'string', ['string']), // filename
  extract: Module.cwrap('extract_pcap', 'string', ['string', 'string']), // ssrc, filename
  decrypt: Module.cwrap('decrypt_pcap', 'string', ['string', 'string', 'string']), // ssrc, key, filename
};
```

### Command-Line Usage
```
./dist/rtptool analyze <input file>
```

Extract RTP streams by ssrc prefixed by `0x`
```
./dist/rtptool extract <ssrc> <input file>
```

Decrypt SRTP streams by ssrc using the RFC4568 key

```
./dist/rtptool decrypt <ssrc> <key> <input file>
```
Example Key: `AES_CM_128_HMAC_SHA1_80 inline:fCaLYx1IEhD62eKqFIGOk1qykNikYcamkFVkde1b|2^31|1:1`


### Credits
Based on [srtpdecrypt](jacquy@posteo.de)
