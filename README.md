```
┬─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┬    ┬ ┬┌─┐┌─┐┌┬┐
├┬┘ │ ├─┘ │ │ ││ ││    │││├─┤└─┐│││
┴└─ ┴ ┴   ┴ └─┘└─┘┴─┘  └┴┘┴ ┴└─┘┴ ┴
```

Extract RTP and Decrypt SRTP Audio streams from .PCAP files in the browser using WASM

### Status
* WASM code is working, but experimental

### Build Native
###### x86_64
`./build.sh` 

###### WASM using Docker
`./build-wasm-docker.sh`
```
npm run test
```

-------------------
### WASM Module Usage
Check out the included [example](wasm/dist/api.js) for API usage
- [x] analyze_pcap
- [x] extract_pcap

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
