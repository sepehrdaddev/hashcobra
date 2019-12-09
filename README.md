<img align="left" width="100" height="100" src="/img.png">

# hashcobra

hashcobra Hash Cracking tool.

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
  $ hashcobra -h 1a1dc91c907325c69271ddf0c944bc72 -r rt.db

```

## Description

This tool uses Rainbow tables for cracking hashes <br>
this makes it to be really fast and a lot faster than traditional <br>
hash cracker.

## Build Prerequisites

- [Make](https://www.gnu.org/software/make/) is required.

- [GCC](https://gcc.gnu.org/) 8.0 or above is required.

- [Rocksdb](https://github.com/facebook/rocksdb) most recent verison is required.

- [Openssl](https://github.com/openssl/openssl) most recent verison is required.

## Building

```
$ make
```

## License

This software is distributed under the GNU General Public License version 3 (GPLv3)

## LEGAL NOTICE

THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.

## Get Involved

**Please, send us pull requests!**
