# Remote Timing Attacks are Practical
An (attempted) implementation of the timing attack on OpenSSL 0.9.7 described in "Remote Timing Attacks are Practical", a 2003 paper by David Brumley and Dan Boneh [1].

## Summary
This project consists of two key components:
  1. Server :: An Ubuntu container which runs an Apache server on port 443 at startup. It uses Apache 1.3.27 built with `mod_ssl` 2.8.12 and using OpenSSL 0.9.7 as in the original paper (though its based on `ubuntu:rolling`). `./server/Dockerfile` contains instructions on how this was built. A pre-generated 1024-bit RSA keypair is located in `./server/ssl-certificate` and contains the secrets that the client aims to attract.
  2. Client :: An Ubuntu container which runs a Jupyter notebook on port 8080 at startup. The `./client/attack.py` module contains the entrypoint for the attack, building upong the helper functions in `tls.py` and `timed_messenger.*`. This environment also contains `matplotlib`, `pandas`, `sympy` and others for data analysis.

### Server
TODO

### Client
TODO

## Setup
This project relies heavily on [Docker](https://www.docker.com) and [`docker-compose`](http://docs.docker.com/compose/install). This has only been tested on Linux but I imagine it'll work on Windows and Mac presuming the aforementioned tools are installed and working.

## Usage
Open up a terminal in the root directory and run `docker-compose up`. This will build (if necessary) then start up the server and client containers. Giving you a vulnerable Apache, `mod_ssl` & OpenSSL running on port 443, and a Jupyter notebook with which to mount the attack on port 8080.

Logs for both will be output to the calling terminal.

## References
  1. Brumley, David, and Dan Boneh. "Remote timing attacks are practical." Computer Networks 48.5 (2005): 701-716. [PDF](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf).
