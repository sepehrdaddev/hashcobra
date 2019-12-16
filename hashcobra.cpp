/*******************************************************************************
 * hashcobra - Optimized Dictionary Attack                                     *
 *                                                                             *
 *                                                                             *
 * DESCRIPTION                                                                 *
 * hashcobra - Hash Cracking tool using Optimized dictionary attack            *
 *                                                                             *
 *                                                                             *
 * AUTHOR                                                                      *
 * sepehrdad                                                                   *
 *                                                                             *
 *                                                                             *
 * LICENSE                                                                     *
 * This software is distributed under the GNU General Public License version 3 *
 *                                                                             *
 *                                                                             *
 * LEGAL NOTICE                                                                *
 * THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY    *
 * ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.        *
 * BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.                          *
 *                                                                             *
 ******************************************************************************/

#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <rocksdb/db.h>

#define LTC_NO_TEST
#define LTC_NO_CIPHERS
#define LTC_NO_MODES
#define LTC_NO_MACS
#define LTC_NO_PRNGS
#define LTC_NO_PK
#define LTC_NO_PKCS
#define LTC_NO_MISC
#include <tomcrypt.h>

#define VERSION "v2.0.0-beta"
#define ERR(str) std::cerr << "ERROR: " << str << '\n'

static void banner() { std::cout << "--==[ hashcobra by sepehrdad ]==--\n\n"; }

static void version() { std::cout << "hashcobra " << VERSION << '\n'; }

static void hashing_algorithms() {
  static const char *h_algs[] = {
      "blake2b-160", "blake2b-256", "blake2b-384", "blake2b-512", "blake2s-128",
      "blake2s-160", "blake2s-224", "blake2s-256", "md2",         "md4",
      "md5",         "sha1",        "sha224",      "sha256",      "sha384",
      "sha512",      "sha3-224",    "sha3-256",    "sha3-384",    "sha3-512",
      "keccak-224",  "keccak-256",  "keccak-384",  "keccak-512",  "ripemd-128",
      "ripemd-160",  "ripemd-256",  "ripemd-320",  "whirlpool",   "tiger"};
  std::cout << "Supported hashing algorithms:\n\n";
  for (const auto &alg : h_algs)
    std::cout << "    > " << alg << '\n';
}

static void compression_algorithms() {
  static const char *c_algs[] = {"zstd", "snappy", "zlib", "bzip2",
                                 "lz4",  "lz4hc",  "none"};
  std::cout << "Supported compression algorithms:\n\n";
  for (const auto &alg : c_algs)
    std::cout << "    > " << alg << '\n';
}

static void operations() {
  static const char *oprs[] = {"create", "crack"};
  std::cout << "Supported operations:\n\n";
  for (const auto &opr : oprs)
    std::cout << "    > " << opr << '\n';
}

static void help() {
  std::cout
      << "usage:\n\n"
      << "  hashcobra -o <opr> [options] | [misc]\n\n"
      << "options:\n\n"
      << "  -a <alg>     - hashing algorithm [default: md5]\n"
      << "               - ? to list available algorithms\n"
      << "  -c <alg>     - compression algorithm [default: zstd]\n"
      << "               - ? to list available algorithms\n"
      << "  -h <hash>    - hash to crack\n"
      << "  -r <path>    - rainbow table path [default: hashcobra.db]\n"
      << "  -d <path>    - dictionary file path\n"
      << "  -o <opr>     - operation to do\n"
      << "               - ? to list available operations\n"
      << "misc:\n\n"
      << "  -V           - show version\n"
      << "  -H           - show help\n\n"
      << "example:\n\n"
      << "  # Create md5 rainbow table with zstd compression from rockyou.txt\n"
      << "  $ hashcobra -o create -d rockyou.txt \n\n"
      << "  # Create sha512 rainbow table with no compression from "
         "darkc0de.lst\n"
      << "  $ hashcobra -o create -a sha512 -c none -r rt.db -d "
         "darkc0de.lst\n\n"
      << "  # Crack 1a1dc91c907325c69271ddf0c944bc72 using rt.db\n"
      << "  $ hashcobra -o crack -h 1a1dc91c907325c69271ddf0c944bc72 -r "
         "rt.db\n\n";
}

class database {
  rocksdb::DB *db{};
  rocksdb::Options options{};
  rocksdb::Status status{};

public:
  database(std::string path,
           rocksdb::CompressionType compression = rocksdb::kZSTD) {
    options.create_if_missing = true;
    options.compression = compression;
    status = rocksdb::DB::Open(options, path, &db);
    if (!status.ok()) {
      ERR(status.ToString());
      exit(EXIT_FAILURE);
    }
  }

  void put(const std::string &key, const std::string &value) {
    status = db->Put(rocksdb::WriteOptions(), key, value);
    if (!status.ok()) {
      ERR(status.ToString());
      exit(EXIT_FAILURE);
    }
  }

  void get(const std::string &key, std::string &value) {
    status = db->Get(rocksdb::ReadOptions(), key, &value);
    if (!status.ok()) {
      if (status.IsNotFound()) {
        ERR("Not Found: " + key);
        value.clear();
      } else {
        ERR(status.ToString());
        exit(EXIT_FAILURE);
      }
    }
  }

  ~database() { delete db; }
};

static std::string str2hex(const unsigned char *digest,
                           unsigned int digest_len) {
  char hex_digest[digest_len * 2];
  static const char Hextable[] = "0123456789abcdef";
  for (unsigned i = 0; i < digest_len; ++i) {
    const uint8_t b = digest[i];
    hex_digest[i * 2] = Hextable[b >> 4];
    hex_digest[i * 2 + 1] = Hextable[b & 0xf];
  }
  return std::string(hex_digest, digest_len * 2);
}

static constexpr unsigned int str2int(const char *str, int h = 0) {
  return !str[h] ? 5381 : (str2int(str, h + 1) * 33) ^ str[h];
}

static unsigned char *RIPEMD128(const unsigned char *input, size_t ilen,
                                unsigned char *output) {
  hash_state md;
  rmd128_init(&md);
  rmd128_process(&md, input, ilen);
  rmd128_done(&md, output);
  return output;
}

static unsigned char *RIPEMD160(const unsigned char *input, size_t ilen,
                                unsigned char *output) {
  hash_state md;
  rmd160_init(&md);
  rmd160_process(&md, input, ilen);
  rmd160_done(&md, output);
  return output;
}

static unsigned char *RIPEMD256(const unsigned char *input, size_t ilen,
                                unsigned char *output) {
  hash_state md;
  rmd256_init(&md);
  rmd256_process(&md, input, ilen);
  rmd256_done(&md, output);
  return output;
}

static unsigned char *RIPEMD320(const unsigned char *input, size_t ilen,
                                unsigned char *output) {
  hash_state md;
  rmd320_init(&md);
  rmd320_process(&md, input, ilen);
  rmd320_done(&md, output);
  return output;
}

static unsigned char *MD2(const unsigned char *input, size_t ilen,
                          unsigned char *output) {
  hash_state md;
  md2_init(&md);
  md2_process(&md, input, ilen);
  md2_done(&md, output);
  return output;
}

static unsigned char *MD4(const unsigned char *input, size_t ilen,
                          unsigned char *output) {
  hash_state md;
  md4_init(&md);
  md4_process(&md, input, ilen);
  md4_done(&md, output);
  return output;
}

static unsigned char *MD5(const unsigned char *input, size_t ilen,
                          unsigned char *output) {
  hash_state md;
  md5_init(&md);
  md5_process(&md, input, ilen);
  md5_done(&md, output);
  return output;
}

static unsigned char *SHA1(const unsigned char *input, size_t ilen,
                           unsigned char *output) {
  hash_state md;
  sha1_init(&md);
  sha1_process(&md, input, ilen);
  sha1_done(&md, output);
  return output;
}

static unsigned char *SHA224(const unsigned char *input, size_t ilen,
                             unsigned char *output) {
  hash_state md;
  sha224_init(&md);
  sha224_process(&md, input, ilen);
  sha224_done(&md, output);
  return output;
}

static unsigned char *SHA256(const unsigned char *input, size_t ilen,
                             unsigned char *output) {
  hash_state md;
  sha256_init(&md);
  sha256_process(&md, input, ilen);
  sha256_done(&md, output);
  return output;
}

static unsigned char *SHA384(const unsigned char *input, size_t ilen,
                             unsigned char *output) {
  hash_state md;
  sha384_init(&md);
  sha384_process(&md, input, ilen);
  sha384_done(&md, output);
  return output;
}

static unsigned char *SHA512(const unsigned char *input, size_t ilen,
                             unsigned char *output) {
  hash_state md;
  sha512_init(&md);
  sha512_process(&md, input, ilen);
  sha512_done(&md, output);
  return output;
}

static unsigned char *SHA3_224(const unsigned char *input, size_t ilen,
                               unsigned char *output) {
  hash_state md;
  sha3_224_init(&md);
  sha3_process(&md, input, ilen);
  sha3_done(&md, output);
  return output;
}

static unsigned char *SHA3_256(const unsigned char *input, size_t ilen,
                               unsigned char *output) {
  hash_state md;
  sha3_256_init(&md);
  sha3_process(&md, input, ilen);
  sha3_done(&md, output);
  return output;
}

static unsigned char *SHA3_384(const unsigned char *input, size_t ilen,
                               unsigned char *output) {
  hash_state md;
  sha3_384_init(&md);
  sha3_process(&md, input, ilen);
  sha3_done(&md, output);
  return output;
}

static unsigned char *SHA3_512(const unsigned char *input, size_t ilen,
                               unsigned char *output) {
  hash_state md;
  sha3_512_init(&md);
  sha3_process(&md, input, ilen);
  sha3_done(&md, output);
  return output;
}

static unsigned char *KECCAK_224(const unsigned char *input, size_t ilen,
                                 unsigned char *output) {
  hash_state md;
  sha3_224_init(&md);
  sha3_process(&md, input, ilen);
  keccak_done(&md, output);
  return output;
}

static unsigned char *KECCAK_256(const unsigned char *input, size_t ilen,
                                 unsigned char *output) {
  hash_state md;
  sha3_256_init(&md);
  sha3_process(&md, input, ilen);
  keccak_done(&md, output);
  return output;
}

static unsigned char *KECCAK_384(const unsigned char *input, size_t ilen,
                                 unsigned char *output) {
  hash_state md;
  sha3_384_init(&md);
  sha3_process(&md, input, ilen);
  keccak_done(&md, output);
  return output;
}

static unsigned char *KECCAK_512(const unsigned char *input, size_t ilen,
                                 unsigned char *output) {
  hash_state md;
  sha3_512_init(&md);
  sha3_process(&md, input, ilen);
  keccak_done(&md, output);
  return output;
}

static unsigned char *WHIRLPOOL(const unsigned char *input, size_t ilen,
                                unsigned char *output) {
  hash_state md;
  whirlpool_init(&md);
  whirlpool_process(&md, input, ilen);
  whirlpool_done(&md, output);
  return output;
}

static unsigned char *TIGER(const unsigned char *input, size_t ilen,
                            unsigned char *output) {
  hash_state md;
  tiger_init(&md);
  tiger_process(&md, input, ilen);
  tiger_done(&md, output);
  return output;
}

static unsigned char *BLAKE2B_160(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2b_160_init(&md);
  blake2b_process(&md, input, ilen);
  blake2b_done(&md, output);
  return output;
}

static unsigned char *BLAKE2B_256(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2b_256_init(&md);
  blake2b_process(&md, input, ilen);
  blake2b_done(&md, output);
  return output;
}

static unsigned char *BLAKE2B_384(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2b_384_init(&md);
  blake2b_process(&md, input, ilen);
  blake2b_done(&md, output);
  return output;
}

static unsigned char *BLAKE2B_512(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2b_512_init(&md);
  blake2b_process(&md, input, ilen);
  blake2b_done(&md, output);
  return output;
}

static unsigned char *BLAKE2S_128(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2s_128_init(&md);
  blake2s_process(&md, input, ilen);
  blake2s_done(&md, output);
  return output;
}

static unsigned char *BLAKE2S_160(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2s_160_init(&md);
  blake2s_process(&md, input, ilen);
  blake2s_done(&md, output);
  return output;
}

static unsigned char *BLAKE2S_224(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2s_224_init(&md);
  blake2s_process(&md, input, ilen);
  blake2s_done(&md, output);
  return output;
}

static unsigned char *BLAKE2S_256(const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
  hash_state md;
  blake2s_256_init(&md);
  blake2s_process(&md, input, ilen);
  blake2s_done(&md, output);
  return output;
}

typedef unsigned char *(*hash_func_t)(const unsigned char *, size_t,
                                      unsigned char *);

static void create(std::string &rpath, std::string &dpath,
                   hash_func_t hash_func, unsigned digest_len,
                   rocksdb::CompressionType compression_type) {
  if (!std::filesystem::exists(dpath)) {
    ERR("Dictionary path doesn't exist: " + dpath);
    exit(EXIT_FAILURE);
  }

  database db{rpath, compression_type};
  std::string line{};
  unsigned char digest[digest_len];

  std::ifstream filestream(dpath);
  if (filestream.good() && filestream.is_open()) {
    while (getline(filestream, line)) {
      hash_func((unsigned char *)line.c_str(), line.size(), digest);
      db.put(str2hex(digest, digest_len), line);
    }
    filestream.close();
  } else {
    ERR("Unable to open dictionary file: " + dpath);
    exit(EXIT_FAILURE);
  }
}
static void crack(std::string &hash, std::string &rpath) {
  if (!std::filesystem::exists(rpath)) {
    ERR("Database not found:" + rpath);
    exit(EXIT_FAILURE);
  }

  std::string string{};

  database db{rpath};
  db.get(hash, string);
  if (!string.empty())
    std::cout << hash << ':' << string << '\n';
}

int main(int argc, char *argv[]) {
  banner();

  if (argc < 2) {
    ERR("use -H for help");
    return EXIT_FAILURE;
  }

  int c{0};
  hash_func_t hash_func{MD5};
  unsigned long digest_len{md5_desc.hashsize};
  rocksdb::CompressionType compression_type{rocksdb::kZSTD};
  std::string hash{}, rpath{"hashcobra.db"}, dpath{}, opr{};

  while ((c = getopt(argc, argv, "VHa:c:h:r:d:o:")) != -1) {
    switch (c) {
    case 'a':
      switch (str2int(optarg)) {
      case str2int("md2"):
        hash_func = MD2;
        digest_len = md2_desc.hashsize;
        break;
      case str2int("md4"):
        hash_func = MD4;
        digest_len = md4_desc.hashsize;
        break;
      case str2int("md5"):
        hash_func = MD5;
        digest_len = md5_desc.hashsize;
        break;
      case str2int("sha1"):
        hash_func = SHA1;
        digest_len = sha1_desc.hashsize;
        break;
      case str2int("sha224"):
        hash_func = SHA224;
        digest_len = sha224_desc.hashsize;
        break;
      case str2int("sha256"):
        hash_func = SHA256;
        digest_len = sha256_desc.hashsize;
        break;
      case str2int("sha384"):
        hash_func = SHA384;
        digest_len = sha384_desc.hashsize;
        break;
      case str2int("sha512"):
        hash_func = SHA512;
        digest_len = sha512_desc.hashsize;
        break;
      case str2int("sha3-224"):
        hash_func = SHA3_224;
        digest_len = sha3_224_desc.hashsize;
        break;
      case str2int("sha3-256"):
        hash_func = SHA3_256;
        digest_len = sha3_256_desc.hashsize;
        break;
      case str2int("sha3-384"):
        hash_func = SHA3_384;
        digest_len = sha3_384_desc.hashsize;
        break;
      case str2int("sha3-512"):
        hash_func = SHA3_512;
        digest_len = sha3_512_desc.hashsize;
        break;
      case str2int("keccak-224"):
        hash_func = KECCAK_224;
        digest_len = keccak_224_desc.hashsize;
        break;
      case str2int("keccak-256"):
        hash_func = KECCAK_256;
        digest_len = keccak_256_desc.hashsize;
        break;
      case str2int("keccak-384"):
        hash_func = KECCAK_384;
        digest_len = keccak_384_desc.hashsize;
        break;
      case str2int("keccak-512"):
        hash_func = KECCAK_512;
        digest_len = keccak_512_desc.hashsize;
        break;
      case str2int("ripemd-128"):
        hash_func = RIPEMD128;
        digest_len = rmd128_desc.hashsize;
        break;
      case str2int("ripemd-160"):
        hash_func = RIPEMD160;
        digest_len = rmd160_desc.hashsize;
        break;
      case str2int("ripemd-256"):
        hash_func = RIPEMD256;
        digest_len = rmd256_desc.hashsize;
        break;
      case str2int("ripemd-320"):
        hash_func = RIPEMD320;
        digest_len = rmd320_desc.hashsize;
        break;
      case str2int("whirlpool"):
        hash_func = WHIRLPOOL;
        digest_len = whirlpool_desc.hashsize;
        break;
      case str2int("tiger"):
        hash_func = TIGER;
        digest_len = tiger_desc.hashsize;
        break;
      case str2int("blake2b-160"):
        hash_func = BLAKE2B_160;
        digest_len = blake2b_160_desc.hashsize;
        break;
      case str2int("blake2b-256"):
        hash_func = BLAKE2B_256;
        digest_len = blake2b_256_desc.hashsize;
        break;
      case str2int("blake2b-384"):
        hash_func = BLAKE2B_384;
        digest_len = blake2b_384_desc.hashsize;
        break;
      case str2int("blake2b-512"):
        hash_func = BLAKE2B_512;
        digest_len = blake2b_512_desc.hashsize;
        break;
      case str2int("blake2s-128"):
        hash_func = BLAKE2S_128;
        digest_len = blake2s_128_desc.hashsize;
        break;
      case str2int("blake2s-160"):
        hash_func = BLAKE2S_160;
        digest_len = blake2s_160_desc.hashsize;
        break;
      case str2int("blake2s-224"):
        hash_func = BLAKE2S_224;
        digest_len = blake2s_224_desc.hashsize;
        break;
      case str2int("blake2s-256"):
        hash_func = BLAKE2S_256;
        digest_len = blake2s_256_desc.hashsize;
        break;
      case str2int("?"):
        hashing_algorithms();
        return EXIT_SUCCESS;
      default:
        ERR("Hashing algorithm not supported: " + std::string(optarg));
        return EXIT_FAILURE;
      }
      break;
    case 'c':
      switch (str2int(optarg)) {
      case str2int("zstd"):
        compression_type = rocksdb::kZSTD;
        break;
      case str2int("snappy"):
        compression_type = rocksdb::kSnappyCompression;
        break;
      case str2int("zlib"):
        compression_type = rocksdb::kZlibCompression;
        break;
      case str2int("bzip2"):
        compression_type = rocksdb::kBZip2Compression;
        break;
      case str2int("lz4"):
        compression_type = rocksdb::kLZ4Compression;
        break;
      case str2int("lz4hc"):
        compression_type = rocksdb::kLZ4HCCompression;
        break;
      case str2int("none"):
        compression_type = rocksdb::kNoCompression;
        break;
      case str2int("?"):
        compression_algorithms();
        return EXIT_SUCCESS;
      default:
        ERR("Compression algorithm not supported: " + std::string(optarg));
        return EXIT_FAILURE;
      }
      break;
    case 'h':
      hash = optarg;
      break;
    case 'r':
      rpath = optarg;
      break;
    case 'd':
      dpath = optarg;
      break;
    case 'o':
      opr = optarg;
      break;
    case 'V':
      version();
      return EXIT_SUCCESS;
    case 'H':
      help();
      return EXIT_SUCCESS;
    default:
      return EXIT_FAILURE;
    }
  }

  switch (str2int(opr.c_str())) {
  case str2int("create"):
    if (dpath.empty()) {
      ERR("No dictionary selected");
      return EXIT_FAILURE;
    }
    create(rpath, dpath, hash_func, digest_len, compression_type);
    break;
  case str2int("crack"):
    if (hash.empty()) {
      ERR("No hash selected");
      return EXIT_FAILURE;
    }
    crack(hash, rpath);
    break;
  case str2int("?"):
    operations();
    return EXIT_SUCCESS;
  case str2int(""):
    ERR("No operation selected");
    return EXIT_FAILURE;
  default:
    ERR("Operation not supported: " + opr);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}