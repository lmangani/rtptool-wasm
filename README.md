```
┬─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┬    ┬ ┬┌─┐┌─┐┌┬┐
├┬┘ │ ├─┘ │ │ ││ ││    │││├─┤└─┐│││
┴└─ ┴ ┴   ┴ └─┘└─┘┴─┘  └┴┘┴ ┴└─┘┴ ┴
```

Extract RTP and Decrypt SRTP Audio streams from .PCAP files

### Status
* WASM code is unstable, experimental

### Build Native
###### x86_64
`./build.sh` 

###### WASM via Docker
`./build-wasm-docker.sh`
```
npm run test
```

-------------------

### Usage
Analyze the PCAP for streams
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
