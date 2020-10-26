# RTPtool-WASM
```
┬─┐┌┬┐┌─┐┌┬┐┌─┐┌─┐┬  
├┬┘ │ ├─┘ │ │ ││ ││  
┴└─ ┴ ┴   ┴ └─┘└─┘┴─┘
```

Extract RTP and Decrypt SRTP Audio streams from .PCAP files

### Status
* Unstable, Broken, Experimental

### Usage
Analyze the PCAP for streams
```
./dist/rtptool analyze <input file>
```

Extract RTP streams by ssrc prefixed by `0x`
```
./dist/rtptool extract <ssrc> <input file>
```

Decrypt SRTP streams by ssrc using the RFC4568 key extracted from SIP (`AES_CM_128_HMAC_SHA1_80 inline:fCaLYx1IEhD62eKqFIGOk1qykNikYcamkFVkde1b|2^31|1:1`)

```
./dist/rtptool decrypt <ssrc> <key> <input file>
```


### Credits
Based on [srtpdecrypt](jacquy@posteo.de)