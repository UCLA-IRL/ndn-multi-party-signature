# MicroBenchmark

## Environment

Hardware: 
MacBook Pro (2015)
2.2 GHz Quad-Core Intel Core i7
16 GB 1600 MHz DDR3

Curve: 
BLS12-381 (about 128bit security)

## Key and Signature Size

pub key size: 48
sig size: 96

## Network Round Trips

packet size: 
optimal scenario: 2 round trips

## Computation Overhead

1 signer:
Signer generating key pair: 260µs
Signer generating signature piece: 1446µs
Initiator aggregating signature pieces of size1: 21µs
Verifier verifying signer lists: 2µs
Verifier aggregating public keys of size 1: 0µs
Verifier verifying BLS signature: 2983µs

4 signers:
Signer generating key pair: 245µs
Signer generating signature piece: 1344µs
Initiator aggregating signature pieces of size 4: 63µs
Verifier verifying signer lists: 2µs
Verifier aggregating public keys of size 4: 6µs
Verifier verifying BLS signature: 2829µs