<img align="left" width="100" height="100" src="/img.png">

# hashcobra

hashcobra Hash Cracking tool.

## Description

This tool uses a new method to crack hashes.
With the help of rainbow tables concept this tool generates rainbow tables
from wordlists to heavily optimize the cracking process.

## Usage

```
$ ./hashcobra -H
--==[ hashcobra by sepehrdad ]==--

usage:

  hashcobra -o <opr> [options] | [misc]

options:

  -a <alg>     - hashing algorithm [default: md5]
               - ? to list available algorithms
  -c <alg>     - compression algorithm [default: zstd]
               - ? to list available algorithms
  -h <hash>    - hash to crack
  -r <path>    - rainbow table path [default: hashcobra.db]
  -d <path>    - dictionary file path
  -o <opr>     - operation to do
               - ? to list available operations
misc:

  -V           - show version
  -H           - show help

example:

  # Create md5 rainbow table with zstd compression from rockyou.txt
  $ hashcobra -o create -d rockyou.txt

  # Create sha512 rainbow table with no compression from darkc0de.lst
  $ hashcobra -o create -a sha512 -c none -r rt.db -d darkc0de.lst

  # Crack 1a1dc91c907325c69271ddf0c944bc72 using rt.db
  $ hashcobra -o crack -h 1a1dc91c907325c69271ddf0c944bc72 -r rt.db

```

### Supported Hashing Algorithms

- blake2b-160
- blake2b-256
- blake2b-384
- blake2b-512
- blake2s-128
- blake2s-160
- blake2s-224
- blake2s-256
- md2
- md4
- md5
- sha1
- sha224
- sha256
- sha384
- sha512
- sha3-224
- sha3-256
- sha3-384
- sha3-512
- keccak-224
- keccak-256
- keccak-384
- keccak-512
- ripemd-128
- ripemd-160
- ripemd-256
- ripemd-320
- whirlpool
- tiger

### Supported Compression Algorithms

- zstd
- snappy
- zlib
- bzip2
- lz4
- lz4hc

## Build Prerequisites

- [Make](https://www.gnu.org/software/make/) is required.

- [GCC](https://gcc.gnu.org/) 8.0 or above is required.

- [Rocksdb](https://github.com/facebook/rocksdb) most recent verison is required.

## Downloading

Because hashcobra relies on an externally linked repository, the --recursive flag must be passed with the git clone command

```
git clone --recursive https://github.com/sepehrdaddev/hashcobra.git
```

## Building

```
$ make
```

## Installing

```
$ make install
```

## License

This software is distributed under the GNU General Public License version 3 (GPLv3)

## LEGAL NOTICE

THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.

## Get Involved

**Please, send us pull requests!**
