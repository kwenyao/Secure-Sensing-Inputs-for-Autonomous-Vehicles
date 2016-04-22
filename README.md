# Secure Sensing inputs for Autonomous Vehicles
This project aims to secure the insecure communication channels within the sensor network in an autonomous vehicle using low cost hardware such as the Beaglebone Black and the Cryptocape.

## Setting up the Beaglebone Black
To set up a new board, follow the instructions in the file [BEAGLEBONE_SETUP](https://github.com/kwenyao/Secure-Sensing-Inputs-for-Autonomous-Vehicles/blob/master/BEAGLEBONE_SETUP).

## Creating Certificates
After setting up the boards, run compile.sh. Do take note of the directories and paths of the various libraries and make the necessary changes.

On the board acting as a CA, run the following
```bash
sudo ./cagen.exe
```
This will generate the root certificate

To create an intermediate certificate:

1. Generate a certificate signing request: `sudo ./gencsr.exe`
2. Send the .csr over to the CA
3. On the CA, sign the CSR: `sudo ./signcsr.exe`

For communication, each board should have the root certificate and the intermediate certificate of the other board which it wants to communicate with.

##Running the Protocol
1. On the receiving board (board connected to CPU), run `sudo ./b.exe`
2. On the sending board (board connected to sensors), run `sudo ./a.exe`

Note: b.exe must be running for a.exe to work.
