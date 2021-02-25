# ndn-multi-party-signature

Goals:

* NDN-format signature based on BLS (Boneh–Lynn–Shacham) digital signature over BLS(Barreto-Lynn-Scott) 12-381 curve.
* Multi-party signature negotiation protocol
* Multi-party signature verification scheme with enhanced NDN Trust Schema

## Build

Build without unit tests:

```bash
mkdir build
cd build
cmake ..
make
```

Build with unit tests:

```bash
mkdir build && cd build
cmake -DHAVE_TESTS=1 -DCMAKE_BUILD_TYPE=Release .. 
make
./unit-tests
```

## Progress Track

* [x] The crypto operations of players
* [x] Encoding/decoding of BLS signature info and signature value
* [x] Schema file parsing
* [x] Negotiation protocol
* [x] Verification
* [x] Replacement when some signers are not available
* [ ] Load public key from files

## Contact

* Zhiyi Zhang (zhiyi@cs.ucla.edu)
* Siqi Liu (tylerliu@g.ucla.edu)
