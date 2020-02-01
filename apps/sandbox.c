// @ref:qc-tesc-openssl-sandbox
// main: openssl/sandbox.c
// mirror: tesc openssl_.c

// https://www.openssl.org/docs/man3.1/man3/

// https://github.com/wataash/libwutils/blob/dd8304e/wutils.cc#L19-L51
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>

#include <assert.h> // assert()
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h> // NULL
#include <stdio.h>
#include <stdlib.h> // exit() EXIT_FAILURE
#include <string.h> // strlen
#include <sys/socket.h>
#include <unistd.h> // STDERR_FILENO

#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/bio.h> // BIO BIO_*()
#include <openssl/bioerr.h>
#include <openssl/bn.h> // BIGNUM BN_*()
#include <openssl/buffer.h>
#include <openssl/buffererr.h>
#include <openssl/cms.h> // CMS_*()
#include <openssl/conf.h>
#include <openssl/crypto.h> // OPENSSL_secure_malloc()
#include <openssl/cryptoerr.h>
#include <openssl/dh.h> // DH DH_*()
#include <openssl/engine.h>
#include <openssl/err.h> // ERR_STATE ERR_*() SSLerr()
#include <openssl/evp.h> // EVP_*()
#include <openssl/rsa.h>
#include <openssl/ssl.h>    // SSL_CTX SSL_CTX_new()
#include <openssl/sslerr.h> // SSL_F_SSL_CTX_NEW SSL_R_NULL_SSL_METHOD_PASSED

char *sandbox_default_config_file = NULL;
BIO *sandbox_bio_in = NULL;
BIO *sandbox_bio_out = NULL;
BIO *sandbox_bio_err = NULL;

#define default_config_file sandbox_default_config_file
#define bio_in sandbox_bio_in;
#define bio_out sandbox_bio_out;
#define bio_err sandbox_bio_err;

#define die(format, ...) die_(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define die_SSL(ssl, rv, format, ...) die_SSL_(__FILE__, __LINE__, ssl, rv, format, ##__VA_ARGS__)

__attribute__((__format__(__printf__, 3, 0))) static void verror(const char *file, unsigned int line, const char *format, va_list ap) {
  fprintf(stderr, "%s:%u die: ", file, line);
  vfprintf(stderr, format, ap);
  if (errno == 0) {
    fprintf(stderr, "\n");
  } else {
    // OpenSSL APIで失敗してもerror stackに積まない場合があるので errno は必ず出力しておく
    // 例: SSL_CTX_new() -> OPENSSL_init_ssl() -> OPENSSL_init_crypto() -> CRYPTO_THREAD_run_once() -> __pthread_once_slow() -> ossl_init_base_ossl_() -> ossl_init_base() -> CRYPTO_THREAD_lock_new() -> CRYPTO_zalloc() -> CRYPTO_malloc() ENOMEM
    // 1024: https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/string/strerror.c#L42
    char buf[1024];
    strerror_r(errno, buf, sizeof(buf));
    fprintf(stderr, ": %s\n", buf);
  }
  ERR_print_errors_fp(stderr);
}

__attribute__((__format__(printf, 3, 4))) _Noreturn static void die_(const char *file, unsigned int line, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  verror(file, line, format, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

__attribute__((__format__(printf, 5, 6))) _Noreturn static void die_SSL_(const char *file, unsigned int line, SSL *ssl, int rv, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  verror(file, line, format, ap);
  va_end(ap);
  int error = SSL_get_error(ssl, rv);
  if (error != SSL_ERROR_NONE && error != SSL_ERROR_SYSCALL)
    fprintf(stderr, "SSL error: %d\n", error);
  exit(EXIT_FAILURE);
}

// -----------------------------------------------------------------------------
// BIO

static void bio(void) {
  BIO *bio;

  bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE);
  if (bio == NULL) {
    // ERR_print_errors_fp() calls BIO_new_fd() again! but it's OK; TODO
    die("BIO_new_fd");
  }

  if (BIO_printf(bio, "hello BIO\n") <= 0)
    die("BIO_printf");

  // BIO_printf() -> BIO_vprintf() hugebuf[1024*2] dynbuf
  // no malloc
  for (size_t i = 0; i < 1024; i++) {
    if (BIO_printf(bio, "%04zu", i) <= 0)
      die("BIO_printf");
  }

#define s10 "123456789\n"
#define s100 s10 s10 s10 s10 s10 s10 s10 s10 s10 s10
#define s1000 s100 s100 s100 s100 s100 s100 s100 s100 s100 s100
  // BIO_printf() -> BIO_vprintf() hugebuf[1024*2] dynbuf -> _dopr() buffer
  //   -> doapr_outch() *buffer
  // OPENSSL_malloc(3072), OPENSSL_realloc(4096), 5120, 6144
  // BUFFER_INC 1024 ずつ増える
  // reallocがO(N)回発生するのは効率大丈夫なんかなあ
  //   exponentialにしたほうがいいような
  //   @ref:qc-openssl-comment-json だと20000文字あるので20回くらい起きるぞ
  //   TODO: malloc読む
  if (BIO_printf(bio, s1000 s1000 s1000 s1000 s1000 s1000) <= 0)
    die("BIO_printf");

  // BIO_free(bio);

  // BIO *BIO_new_file(const char *filename, const char *mode);
  // BIO *BIO_new_fp(FILE *stream, int close_flag);
  // BIO *BIO_new_mem_buf(const void *buf, int len);
  // BIO *BIO_new_dgram(int fd, int close_flag);
  // BIO *BIO_new_dgram_sctp(int fd, int close_flag);
  // BIO *BIO_new_socket(int sock, int close_flag);
  // BIO *BIO_new_connect(const char *host_port);
  // BIO *BIO_new_accept(const char *host_port);
  // BIO *BIO_new_fd(int fd, int close_flag);

  // BIO *BIO_push(BIO *b, BIO *append);
  // BIO *BIO_pop(BIO *b);
  // BIO *BIO_find_type(BIO *b, int bio_type);
  // BIO *BIO_next(BIO *b);
  // BIO *BIO_get_retry_BIO(BIO *bio, int *reason);
  // BIO *BIO_dup_chain(BIO *in);

  {
    const char *bytes = "hello";
    (void)BIO_dump(bio, bytes, (int)strlen(bytes));     // strlen: 5
    (void)BIO_dump(bio, bytes, (int)strlen(bytes) + 1); // 6 (including NUL)
  }

  (void)BIO_dump(bio, s100, strlen(s100)); // 100
  (void)BIO_dump(bio, s100, sizeof(s100)); // 101 including NUL
  (void)BIO_dump_fp(stderr, s100, sizeof(s100));
  (void)BIO_dump_indent(bio, s100, sizeof(s100), 2);
  (void)BIO_dump_indent_fp(stderr, s100, sizeof(s100), 2);
  (void)BIO_hex_string(bio, 4, 10, (unsigned char *)s100, sizeof(s100));

  BIO_free(bio);
}

// -----------------------------------------------------------------------------
// BN

static void bn(void) {
  BIGNUM *bn;

  // https://www.openssl.org/docs/man1.1.1/man3/BN_new.html
  bn = BN_new();
  if (bn == NULL)
    die("BN_new");
  (void)BN_secure_new;
  // https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_secure_malloc.html
  (void)OPENSSL_secure_malloc(0);

  BN_clear(bn);

  // https://www.openssl.org/docs/man1.1.1/man3/BN_bn2bin.html
  (void)BN_bn2bin;
  (void)BN_bn2hex;
  (void)BN_bn2dec;

  // https://www.openssl.org/docs/man1.1.1/man3/BN_cmp.html
  (void)BN_cmp;
  (void)BN_ucmp;
  (void)BN_is_zero;
  (void)BN_is_one;
  (void)BN_is_word;
  (void)BN_is_odd;

  // https://www.openssl.org/docs/man1.1.1/man3/BN_copy.html
  (void)BN_copy;
  (void)BN_dup;
  (void)BN_with_flags;
  (void)BN_print;

  if (BN_print_fp(stdout, bn) != 1) // 1
    die("BN_print_fp");
  printf("\n");
  if (BN_add_word(bn, 1) != 1)
    die("BN_add_word");
  if (BN_print_fp(stdout, bn) != 1) // 2
    die("BN_print_fp");
  printf("\n");

  BN_free(bn);
  bn = NULL;
  BN_clear_free(bn); // noop because bn == NULL
  bn = NULL;
  (void)bn;
}

// -----------------------------------------------------------------------------
// DH

static void dh(void) {
  DH *dh;

  // https://www.openssl.org/docs/man1.1.1/man3/DH_new.html
  dh = DH_new();
  if (dh == NULL)
    die("DH_new");

  if (BN_hex2bn(NULL, "-000") == 0) // returns 4; number of '-' and digits
    die("BN_hex2bn");

  BIGNUM *p = NULL, *q = NULL, *g = NULL;
  if (BN_hex2bn(&p, "b") == 0) // 0xb: 11
    die("BN_hex2bn");
  if (BN_hex2bn(&p, "b") == 0) // no malloc in bn_expand()
    die("BN_hex2bn");
  if (BN_hex2bn(&q, "3") == 0)
    die("NB_hex2bn");
  if (BN_hex2bn(&g, "2") == 0)
    die("NB_hex2bn");

  DH_set0_pqg(dh, NULL, NULL, NULL); // noop
  DH_set0_pqg(dh, p, q, g);          // 1

  // dh->pub_key, dh->priv_key: NULL

  // p 11
  // q 3 = priv_key
  // g 2
  // pub_key = 2**3 % 11 = 8
  if (DH_generate_key(dh) != 1)
    die("DH_generate_key");

  {
    unsigned char buf[16] __attribute__((unused));

    // BN_bn2bin(dh->pub_key, buf); // 4???...
    // BN_bn2binpad(dh->pub_key, buf, sizeof(buf)); // 0000...0004
    // BN_bn2dec(dh->pub_key); // "4"
    // BN_bn2hex(dh->pub_key); // "04"
    // ん？8じゃない？

    // BN_bn2bin(dh->priv_key, buf);// 2???...
    // BN_bn2binpad(dh->priv_key, buf, sizeof(buf)); // 0000...0002
    // BN_bn2dec(dh->priv_key); // "4"
    // BN_bn2hex(dh->priv_key); // "04"
    // 3じゃない？

    __asm__("nop");
  }

  BIGNUM *pub_key = NULL, *priv_key = NULL;
  if (BN_hex2bn(&pub_key, "8") == 0)
    die("NB_hex2bn");
  if (BN_hex2bn(&priv_key, "3") == 0)
    die("NB_hex2bn");
  if (DH_set0_key(dh, pub_key, priv_key) != 1)
    die("DH_set0_key");

  // TODO: 鍵交換

  DH_free(dh);
  dh = NULL;
}

// -----------------------------------------------------------------------------
// ERR

// SSL_CTX_new() が ENOMEM 等で失敗した場合、
// OPENSSL_malloc() の失敗と同様に errno のみセットして error stack は積まない。
// 両方チェックするのがいいかな:
//
//   errno = 0;         // init
//   ERR_clear_error(); // init
//
//   if (some_openssl_function() == -1) {
//     if (errno != 0)
//       perror("some_openssl_function");
//     ERR_print_errors_fp(stderr);
//   }

static void err(void) {
  ERR_STATE *es = ERR_get_state(); // thread-local
  if (es == NULL)
    die("ERR_get_state");

  SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
  // == ERR_PUT_error(ERR_LIB_SSL, SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED, __FILE__, __LINE__)
  //    ERR_PUT_error(lib, func, reason, file, line)
  // -> ERR_PACK(ERR_LIB_SSL, SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED)
  //    ERR_PACK(lib, func, reason)

  (void)es->err_flags[1];      // 0 (others: ERR_FLAG_MARK ERR_FLAG_CLEAR)
  (void)es->err_buffer[1];     // 0x140a90c4 ERR_PACK(ERR_LIB_SSL, SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED)
  (void)es->err_data[1];       // NULL
  (void)es->err_data_flags[1]; // 0 (others: ERR_TXT_MALLOCED ERR_TXT_STRING)
  (void)es->err_file[1];       // "../apps/openssl.c"
  (void)es->err_line[1];       // 254
  (void)es->top;               // 1
  (void)es->bottom;            // 0

  assert(SSL_CTX_new(NULL) == NULL);
  // -> SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);

  (void)es->err_buffer[2];
  (void)es->err_file[2]; // "../ssl/ssl_lib.c"
  (void)es->err_line[2]; // 3021
  (void)es->top;         // 2
  (void)es->bottom;      // 0

  assert(OPENSSL_malloc(1ULL * 1024 * 1024 * 1024 * 1024) == NULL); // 1TiB; malloc() ENOMEM, no ERR_PUT_error()
  perror("OPENSSL_malloc");

  // https://www.openssl.org/docs/man1.1.1/man3/ERR_get_error.html

  {
    const char *file, *data;
    int line, flags;

    (void)ERR_get_error;
    (void)ERR_get_error_line;
    unsigned long ul = ERR_get_error_line_data(&file, &line, &data, &flags); // pop first

    (void)es->err_buffer[1]; // 0 (es->err_buffer[i] = 0;)
    (void)es->top;           // 2
    (void)es->bottom;        // 1
    (void)file;              // "../apps/openssl.c"
    (void)line;              // 254
    (void)data;              // "" (if (es->err_data[i] == NULL) { *data = "";)
    (void)flags;             // 0
    assert(ERR_GET_LIB(ul) == ERR_LIB_SSL);
    // assert(ERR_GET_FUNC(ul) == SSL_F_SSL_CTX_NEW); // removed in OpenSSL 3?
    assert(ERR_GET_REASON(ul) == SSL_R_NULL_SSL_METHOD_PASSED);

    // https://www.openssl.org/docs/man1.1.1/man3/ERR_error_string_n.html
    char buf[1024];
    ERR_error_string_n(ul, buf, sizeof(buf));
    (void)(char *) buf;                // "error:140A90C4:SSL routines:func(169):reason(196)"
    (void)ERR_lib_error_string(ul);    // "SSL routines"
    (void)ERR_func_error_string(ul);   // NULL
    (void)ERR_reason_error_string(ul); // NULL
  }

  {
    const char *file, *data;
    int line, flags;

    // peek first
    // get_error_values() で if (inc) が実行されない
    (void)ERR_peek_error();
    (void)ERR_peek_error_line_data(&file, &line, &data, &flags);

    // peek last
    // get_error_values() で
    //    if (top)
    //         i = es->top;            /* last error */
    (void)ERR_peek_last_error();
    (void)ERR_peek_last_error_line_data(&file, &line, &data, &flags);
  }

  // https://www.openssl.org/docs/man1.1.1/man3/ERR_print_errors_fp.html
  // pops all
  ERR_print_errors_fp(stderr);
  (void)ERR_print_errors;
  (void)ERR_print_errors_cb;

  assert(ERR_get_error() == 0); // no more error

  __asm__("nop");
}

// -----------------------------------------------------------------------------
// EVP - GCM

// ref:
// https://www.openssl.org/docs/man3.1/man3/EVP_CIPHER_fetch.html
// openssl/test/evp_extra_test.c
// @ref:qc-openssl-comment-link1
// @ref:qc-openssl-comment-link2
static void evp_gcm(void) {
  static const unsigned char key[32] = {0x4d, 0x47, 0x6f, 0x6b, 0x56, 0x74, 0x75, 0x6b, 0x49, 0x52, 0x76, 0x42, 0x32, 0x32, 0x32, 0x61, 0x35, 0x37, 0x77, 0x33, 0x68, 0x79, 0x58, 0x52, 0x50, 0x57, 0x43, 0x34, 0x53, 0x55, 0x64, 0x58}; // 4d476f6b5674756b495276423232326135377733687958525057433453556458 "MGokVtukIRvB222a57w3hyXRPWC4SUdX"
  static const unsigned char nonce[12] = {0x22, 0x28, 0x12, 0xa0, 0x2f, 0xcf, 0x65, 0x40, 0x73, 0x7e, 0xdd, 0xe0}; // 222812a02fcf6540737edde0; + 00000001 (counter) = IV (16 bytes)

  // encrypt
  {
    static const unsigned char plain[6] = "aabbcc";

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
      goto err;

    type = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (type == NULL)
      goto err;

    // EVP_aes_256_gcm()
    // https://www.openssl.org/docs/man3.1/man3/EVP_aes_256_gcm.html
    // > NOTES
    // https://www.openssl.org/docs/man3.1/man3/EVP_CIPHER_fetch.html
    // > this is not recommended for new applications
    // EVP_CIPHER *type = EVP_aes_256_gcm();

    // > The functions EVP_EncryptInit(), EVP_EncryptInit_ex(), EVP_EncryptFinal(), EVP_DecryptInit(), EVP_DecryptInit_ex(), EVP_CipherInit(), EVP_CipherInit_ex() and EVP_CipherFinal() are obsolete but are retained for compatibility with existing code.
    // > New code should use EVP_EncryptInit_ex2(), EVP_EncryptFinal_ex(), EVP_DecryptInit_ex2(), EVP_DecryptFinal_ex(), EVP_CipherInit_ex2() and EVP_CipherFinal_ex() because they can reuse an existing context without allocating and freeing it up on each call.
    if (EVP_EncryptInit_ex2(ctx, type, key, nonce, NULL) != 1)
      goto err;

    if (0) {
      // nonce length 12: default
      //
      // #0  EVP_CIPHER_get_iv_length (cipher=0x55555569edb0) at ../crypto/evp/evp_lib.c:502
      //     // cipher->type_name: "AES-256-GCM"
      //     return cipher->iv_len; // 12
      //     // /home/wsh/qc/openssl/crypto/evp/e_aes.c
      //     //   BLOCK_CIPHER_custom(NID_aes, 256, 16, 12, ocb, OCB, // ivlen: 12
      //     //                       EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
      // #1  0x00007ffff7b6477c in EVP_CIPHER_CTX_get_iv_length (ctx=0x55555567a2a0) at ../crypto/evp/evp_lib.c:508
      // #2  0x00007ffff7b5ceb0 in evp_cipher_init_internal (ctx=0x55555567a2a0, cipher=0x55555569edb0, impl=0x0, key=0x7fffffffd2c0 "MGokVtukIRvB222a57w3hyXRPWC4SUdX\200\003", iv=0x7fffffffd2a0 "\"(\022\240/\317e@s~\335", <incomplete sequence \340>, enc=1, params=0x0) at ../crypto/evp/evp_enc.c:238
      // #3  0x00007ffff7b5d58f in EVP_CipherInit_ex2 (ctx=0x55555567a2a0, cipher=0x55555569edb0, key=0x7fffffffd2c0 "MGokVtukIRvB222a57w3hyXRPWC4SUdX\200\003", iv=0x7fffffffd2a0 "\"(\022\240/\317e@s~\335", <incomplete sequence \340>, enc=1, params=0x0) at ../crypto/evp/evp_enc.c:402
      // #4  0x00007ffff7b5d830 in EVP_EncryptInit_ex2 (ctx=0x55555567a2a0, cipher=0x55555569edb0, key=0x7fffffffd2c0 "MGokVtukIRvB222a57w3hyXRPWC4SUdX\200\003", iv=0x7fffffffd2a0 "\"(\022\240/\317e@s~\335", <incomplete sequence \340>, params=0x0) at ../crypto/evp/evp_enc.c:462
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
        goto err;
    }

    unsigned char out[1024];
    int outl;
    if (EVP_EncryptUpdate(ctx, out, &outl, plain, (int)sizeof(plain)) != 1) // outl: 6 out: ciphertext 596fcb3a68e4
      goto err;

    if (EVP_EncryptFinal_ex(ctx, out, &outl) != 1)
      goto err;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)sizeof(tag), tag) != 1) // tag: 86966ec3f19a309a4d3db87c7d343e7a 16 bytes
      goto err;

    goto free_;

err:
    ERR_print_errors_fp(stderr);
free_:
    EVP_CIPHER_free(type);
    EVP_CIPHER_CTX_free(ctx);
  }

  // decrypt
  {
    static const unsigned char encrypted[6] = {0x59, 0x6f, 0xcb, 0x3a, 0x68, 0xe4}; // 596fcb3a68e4
    static /* const */ unsigned char tag[16] = {0x86, 0x96, 0x6e, 0xc3, 0xf1, 0x9a, 0x30, 0x9a, 0x4d, 0x3d, 0xb8, 0x7c, 0x7d, 0x34, 0x3e, 0x7a}; // 86966ec3f19a309a4d3db87c7d343e7a; change this -> EVP_DecryptFinal_ex() fails

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
      goto err2;

    type = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (type == NULL)
      goto err2;

    if (EVP_DecryptInit_ex2(ctx, type, key, nonce, NULL) != 1)
      goto err2;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)sizeof(tag), tag) != 1)
      goto err2;

    unsigned char out[1024];
    int outl;
    if (EVP_DecryptUpdate(ctx, out, &outl, encrypted, (int)sizeof(encrypted)) != 1) // outl: 6 out: "aabbcc"
      goto err2;

    if (EVP_DecryptFinal_ex(ctx, out, &outl) != 1)
      goto err2; // N.B. no ERR on authentication failure

    goto free2;

err2:
    ERR_print_errors_fp(stderr);
free2:
    EVP_CIPHER_free(type);
    EVP_CIPHER_CTX_free(ctx);
  }
}

// -----------------------------------------------------------------------------

void sandbox(void) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("OPENSSL_VERSION_NUMBER: 0x%lxL\n",
         (unsigned long)OPENSSL_VERSION_NUMBER);

  bio();
  bn();
  dh();
  err();
  evp_gcm();
}
