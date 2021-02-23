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
Signer generating key pair: 260/240/242/250/251µs
Signer generating signature piece: 1446/1549/1404/1332/1267µs
Initiator aggregating signature pieces of size1: 21µs
Verifier verifying signer lists: 2/2/2/2/2µs
Verifier aggregating public keys of size 1: 0µs
Verifier verifying BLS signature: 2983/3147/3068/3227/3301µs

4 signers:
Signer generating key pair: 245/240/260/252/248µs
Signer generating signature piece: 1344/1503/1424/1309µs
Initiator aggregating signature pieces of size 4: 1185/1086/1452/1288/1084µs
Verifier verifying signer lists: 2/3/2/2/3µs
Verifier aggregating public keys of size 4: 6/6/6/6/9µs
Verifier verifying BLS signature: 2829/3091/3165/3165/3513µs