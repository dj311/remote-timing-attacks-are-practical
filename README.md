# Remote Timing Attacks are Practical
This repo contains an (attempted) implementation of the timing attack on OpenSSL 0.9.7 described in "Remote Timing Attacks are Practical", a 2003 paper by David Brumley and Dan Boneh [1]. The attack works against OpenSSL 0.9.7, and was the motivation for turning on [blinding](https://en.wikipedia.org/wiki/Blinding_\(cryptography\)) by default in 2003 [2].  

I haven't got the attack to work yet (see current project [status](#status)). Hopefully this repo is a good resource for anyone trying to replicate the paper. If you have any advice, or have spotted an error, please do [get in touch](https://daniel.wilshirejones.com/contact.html). I'm keen to get this working! 

## Theory
The general gist of the attack is that the time taken to decrypt `g` with a private key `d`, `g^d % N`, is dependant on the relationship between `g` and the factors of `N=p*q`. The paper combines two time leaks sourced from implementation details of this modular exponentiation. The first is from their use of [Montgomery](https://en.wikipedia.org/wiki/Montgomery_modular_multiplication) multiplication, and the second from [Karatsuba](https://en.wikipedia.org/wiki/Karatsuba_algorithm) multiplication.

To get this to work in practice, we need a way to send a variety of `g` values to the server, and time their decryption. The paper accomplishes this by sending specially crafted `g`'s in place of the pre-master secret in the TLS handshake. This causes the handshake to fail. The time between sending the pre-master secret, and receiving failure message from the server is recorded as the decryption time.

There's quite a bit more to this attack than Ive explained here, but thats a high-level overview of the core parts. The papers explanations are clearer than what I've written above, and relatively short. It's definitely worth a read.

## Practice
This project consists of two key components:
  1. Server :: Runs the vulnerable Apache server on port 443.
  2. Client :: Runs a Jupyter notebook server on port 8080. This is used to mount the attack and perform analysis.

### Server
This is an Ubuntu container running Apache 1.3.27 built with `mod_ssl` 2.8.12 and using OpenSSL 0.9.7 (the versions used in the paper). The [`Dockerfile`](./server/Dockerfile) contains instructions on how this is built and is the primary piece of code in the server component.

Upon build, the OpenSSL source code is [patched](.server/djwj-openssl-patch) to add two pieces of functionality:

  1. Logging messages help trace the execution of OpenSSL when it's decrypted the Client Key Exchange message. Reassuring us that the correct bug is being triggered.
  2. Record and log the time taken for `RSA_private_decrypt` routine to calculate the `g^d % N` decryption.

A pre-generated 1024-bit RSA keypair is located in `./server/ssl-certificate` and contains the secrets that the client aims to extract. The certificate is baked in to the image at build time, so a `docker-compose build server` is needed if you want to change them.

Differences to the original paper:
  - Runs on the current Ubuntu rolling release rather than Red Hat 7.
  - Compiled using the latest gcc release on Ubuntu, rather than gcc 2.96.
    - This seemed to require some minor changes to the server sources to get it to compile. These can all be seen in the Dockerfile.
  - 64-bit architecture, not 32-bit.
    - I changed some compilation flags to reflect this change.
    - I reckon this should give different results to some described in the paper, but the principles should be the same.
  - I've patched the OpenSSL source as described above.

### Client
This container includes an environment for statistical analysis and some Python modules that implement the actual attack (`attack.py`, `tls.py`, and `timed_messenger.*`).

The `./client/attack.py` module contains the entrypoint for the attack, building upong the helper functions in `tls.py` and `timed_messenger.*`.

The majority of the attack code is written in Python, with the exception of `timed_messenger.*` in C. This module sends a message over an open socket, waits for a response, and times how long the whole thing takes. It does this using the guidance in the "How to Benchmark Code Execution Times" whitepaper from Intel [3].

## Setup
This project relies heavily on [Docker](https://www.docker.com) and [`docker-compose`](http://docs.docker.com/compose/install). This has only been tested on Linux but I imagine it'll work on Windows and Mac presuming the aforementioned tools are installed and working.

## Usage
Open up a terminal in the root directory and run `docker-compose up`. This will build (if necessary) then start up the server and client containers. This gives you a vulnerable Apache, `mod_ssl` & OpenSSL running on port 443, and a Jupyter notebook with which to mount the attack on port 8080.

There's a little bash script for executing the client notebooks from the command line:
```sh
$ docker-compose run --entrypoint=bash execute-notebook <notebook_name>
```

The results will be saved in a separate copy named `<notebook_name>.YYYY-MM-DDTHH-MM-SS.ipynb`.

I use the above to gather new measurements, like so:

```sh
$ # Delete existing measurement files, to signal that new ones must be generated
$ rm client/measurements/bit-samples.txt \
  client/measurements/internal-measurements.txt \
  client/measurements/bruteforce-top-bits.txt
  
$ # Run the attack.ipynb notebook
$ docker-compose run --detach --entrypoint=bash client execute-notebook attack

$ # Gather internal OpenSSL time measurements from the servers stdout:
$ docker-compose logs --no-color --tail=all --follow server \
  | grep "djwj: internal measurement: " \
  > client/measurements/internal-measurements.txt
```

## Status
Log:
  * 2020-02-24 :: fbd7c1672226bb4b6ee6421590dfccf610f64ed3 [🔗](https://github.com/dj311/remote-timing-attacks-are-practical/commit/fbd7c1672226bb4b6ee6421590dfccf610f64ed3) :: The most recent set of measurements includes the internal measurements recorded within OpenSSL alongside those taken from the client container. I haven't been able to extract any useful signal from either of these. However, I believe these show that the network samples (taken with n=400, s=10) track the trend of the internal samples with sufficient acccuracy. I think this means that the problem is that either 1. we aren't triggering the bug 2. the analysis is incorrect.
  * 2020-02-11 :: 00c9848053a419d7ddf055e06126f80bac4f28f6 [🔗](https://github.com/dj311/remote-timing-attacks-are-practical/commit/00c9848053a419d7ddf055e06126f80bac4f28f6) :: When adding the logging code I noticed that the reason the handshake fails (and so the alert type returned by the server) can differ slightly. This is because, once the decryption fails, OpenSSL replaces the pre-master secret with random bytes. Sometimes those bytes will be detected as having the wrong padding whilst, rarely, the padding bytes will turn out to pass the initial sanity checks, and trigger a different error. I don't this alters the attack, but it's a fun tidbit.

## References
  1. Brumley, David, and Dan Boneh. "Remote timing attacks are practical." Computer Networks 48.5 (2005): 701-716. [PDF](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf).
  2. "Timing-based attacks on RSA keys", OpenSSL Security Advisory. 17 March 2003. https://www.openssl.org/news/secadv/20030317.txt.
  3. Gabriele Paoloni. "How to Benchmark Code Execution Times on Intel® IA-32 and IA-64 Instruction Set Architectures". September 2010. [PDF](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf).
