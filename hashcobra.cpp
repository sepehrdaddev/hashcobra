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
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <rocksdb/db.h>

#define VERSION "v2.0.0-beta"
#define ERR(str) std::cerr << "ERROR: " << str << '\n'

static const char *h_algs[] = {"md4",    "md5",    "sha1",  "sha224",
                               "sha256", "sha384", "sha512"};

static const char *c_algs[] = {"zstd", "snappy", "zlib", "bzip2",
                               "lz4",  "lz4hc",  "none"};

static const char *oprs[] = {"create", "crack"};

static void banner() { std::cout << "--==[ hashcobra by sepehrdad ]==--\n\n"; }

static void version() { std::cout << "hashcobra " << VERSION << '\n'; }

static void hashing_algorithms() {
  std::cout << "Supported hashing algorithms:\n\n";
  for (const auto &alg : h_algs)
    std::cout << "    > " << alg << '\n';
}

static void compression_algorithms() {
  std::cout << "Supported compression algorithms:\n\n";
  for (const auto &alg : c_algs)
    std::cout << "    > " << alg << '\n';
}

static void operations() {
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
      << "  $ hashcobra -h 1a1dc91c907325c69271ddf0c944bc72 -r rt.db\n\n";
}

static constexpr unsigned int str2int(const char *str, int h = 0) {
  return !str[h] ? 5381 : (str2int(str, h + 1) * 33) ^ str[h];
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

static std::string hex_digest(const unsigned char *digest,
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
      db.put(hex_digest(digest, digest_len), line);
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
  unsigned digest_len{MD5_DIGEST_LENGTH};
  rocksdb::CompressionType compression_type{rocksdb::kZSTD};
  std::string hash{}, rpath{"hashcobra.db"}, dpath{}, opr{};

  while ((c = getopt(argc, argv, "VHa:c:h:r:d:o:")) != -1) {
    switch (c) {
    case 'a':
      switch (str2int(optarg)) {
      case str2int("md4"):
        hash_func = MD4;
        digest_len = MD4_DIGEST_LENGTH;
        break;
      case str2int("md5"):
        hash_func = MD5;
        digest_len = MD5_DIGEST_LENGTH;
        break;
      case str2int("sha1"):
        hash_func = SHA1;
        digest_len = SHA_DIGEST_LENGTH;
        break;
      case str2int("sha224"):
        hash_func = SHA224;
        digest_len = SHA224_DIGEST_LENGTH;
        break;
      case str2int("sha256"):
        hash_func = SHA256;
        digest_len = SHA256_DIGEST_LENGTH;
        break;
      case str2int("sha384"):
        hash_func = SHA384;
        digest_len = SHA384_DIGEST_LENGTH;
        break;
      case str2int("sha512"):
        hash_func = SHA512;
        digest_len = SHA512_DIGEST_LENGTH;
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