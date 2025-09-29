// oqs_emr.c
// Compile: gcc -O2 -o oqs_emr oqs_emr.c -loqs -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define MAGIC "OQS1"
#define AES_KEYLEN 32
#define IV_LEN 12
#define TAG_LEN 16

// helper: read full file into buffer
static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

// write full buffer to file
static int write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 0; }
    fclose(f);
    return 1;
}

// write uint32 big-endian
static void write_u32(unsigned char *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}
static uint32_t read_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// derive AES-256 key from shared_secret using SHA-256
static void derive_key(const unsigned char *shared, size_t shared_len, unsigned char out_key[AES_KEYLEN]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(shared, shared_len, hash);
    memcpy(out_key, hash, AES_KEYLEN);
    // zero local hash if desired
    OPENSSL_cleanse(hash, sizeof(hash));
}

// === 新增：打印十六进制缓冲区 ===
static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
}

// AES-256-GCM encrypt (plaintext -> ciphertext, outputs iv and tag)
static int aes_gcm_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len,
                           unsigned char *iv, int iv_len,
                           unsigned char **ciphertext, int *ciphertext_len,
                           unsigned char tag[TAG_LEN]) {
    int len;
    int ciphertext_len_local;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    *ciphertext = malloc(plaintext_len);
    if (!*ciphertext) goto done;

    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) goto done;
    ciphertext_len_local = len;

    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) goto done;
    ciphertext_len_local += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) goto done;

    *ciphertext_len = ciphertext_len_local;
    ret = 1;
done:
    if (!ret && *ciphertext) { free(*ciphertext); *ciphertext = NULL; }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// AES-256-GCM decrypt
static int aes_gcm_decrypt(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *iv, int iv_len,
                           const unsigned char tag[TAG_LEN],
                           unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len_local;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    *plaintext = malloc(ciphertext_len);
    if (!*plaintext) goto done;

    if (!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) goto done;
    plaintext_len_local = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) goto done;
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        // tag verification failed
        goto done;
    }
    plaintext_len_local += len;
    *plaintext_len = plaintext_len_local;
    ret = 1;
done:
    if (!ret && *plaintext) { free(*plaintext); *plaintext = NULL; }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s genkey <pub_out> <sec_out>\n"
        "  %s encrypt <pubkey_file> <in_plain_txt> <out_bundle>\n"
        "  %s decrypt <secretkey_file> <in_bundle> <out_plain_txt>\n", prog, prog, prog);
}

// genkey: write raw public_key and secret_key to files
static int cmd_genkey(const char *pub_out, const char *sec_out) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "KEM not available\n");
        return 1;
    }
    unsigned char *pk = malloc(kem->length_public_key);
    unsigned char *sk = malloc(kem->length_secret_key);
    if (!pk || !sk) { fprintf(stderr, "malloc failed\n"); return 1; }

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_keypair failed\n");
        return 1;
    }

    if (!write_file(pub_out, pk, kem->length_public_key)) {
        fprintf(stderr, "write pubkey failed\n");
        return 1;
    }
    if (!write_file(sec_out, sk, kem->length_secret_key)) {
        fprintf(stderr, "write seckey failed\n");
        return 1;
    }
    printf("Generated keypair. pub: %s, sec: %s\n", pub_out, sec_out);

    // 调试输出
    print_hex("Public Key", pk, kem->length_public_key);
    print_hex("Secret Key", sk, kem->length_secret_key);

    OPENSSL_cleanse(pk, kem->length_public_key);
    OPENSSL_cleanse(sk, kem->length_secret_key);
    free(pk); free(sk);
    OQS_KEM_free(kem);
    return 0;
}

// encrypt: read pubkey, encapsulate -> get kem_ct & shared -> derive AES key -> encrypt file -> write bundle
// -------------------- cmd_encrypt（替换旧函数） --------------------
static int cmd_encrypt(const char *pubkey_file, const char *in_plain, const char *out_bundle) {
    size_t pk_len;
    unsigned char *pk = read_file(pubkey_file, &pk_len);
    if (!pk) { fprintf(stderr, "read pubkey failed\n"); return 1; }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) { fprintf(stderr, "KEM new failed\n"); free(pk); return 1; }
    if (pk_len != kem->length_public_key) { fprintf(stderr, "pubkey size mismatch\n"); free(pk); OQS_KEM_free(kem); return 1; }

    unsigned char *kem_ct = malloc(kem->length_ciphertext);
    unsigned char *shared_secret = malloc(kem->length_shared_secret);
    if (!kem_ct || !shared_secret) { fprintf(stderr, "malloc failed\n"); free(pk); OQS_KEM_free(kem); return 1; }

    if (OQS_KEM_encaps(kem, kem_ct, shared_secret, pk) != OQS_SUCCESS) {
        fprintf(stderr, "encaps failed\n"); free(pk); OQS_KEM_free(kem); return 1;
    }

    // derive AES key
    unsigned char aes_key[AES_KEYLEN];
    derive_key(shared_secret, kem->length_shared_secret, aes_key);

    // read plaintext file
    size_t plain_len;
    unsigned char *plain = read_file(in_plain, &plain_len);
    if (!plain) { fprintf(stderr, "read plaintext failed\n"); free(pk); OQS_KEM_free(kem); return 1; }

    unsigned char iv[IV_LEN];
    if (1 != RAND_bytes(iv, IV_LEN)) { fprintf(stderr, "RAND_bytes failed\n"); free(pk); OQS_KEM_free(kem); return 1; }
    unsigned char tag[TAG_LEN];
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    if (!aes_gcm_encrypt(aes_key, plain, (int)plain_len, iv, IV_LEN, &ciphertext, &ciphertext_len, tag)) {
        fprintf(stderr, "AES-GCM encrypt failed\n"); free(pk); OQS_KEM_free(kem); return 1;
    }

    // Extract original filename from in_plain path (basename)
    const char *slash = strrchr(in_plain, '/');
    #ifdef _WIN32
    const char *bs = strrchr(in_plain, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
    #endif
    const char *basename = slash ? slash + 1 : in_plain;
    uint32_t fname_len = (uint32_t)strlen(basename);

    // Build bundle:
    // MAGIC(4) | u32(kem_ct_len) | u32(iv_len) | u32(tag_len) | u32(ct_len) | u32(fname_len) | fname_bytes | kem_ct | iv | tag | ciphertext
    uint32_t kem_ct_len_u32 = (uint32_t)kem->length_ciphertext;
    uint32_t iv_len_u32 = IV_LEN;
    uint32_t tag_len_u32 = TAG_LEN;
    uint32_t ct_len_u32 = (uint32_t)ciphertext_len;

    size_t total = 4 + 4*5 + fname_len + kem_ct_len_u32 + iv_len_u32 + tag_len_u32 + ct_len_u32;
    unsigned char *out = malloc(total);
    if (!out) { fprintf(stderr, "malloc failed\n"); free(pk); OQS_KEM_free(kem); return 1; }
    unsigned char *p = out;
    memcpy(p, MAGIC, 4); p += 4;
    write_u32(p, kem_ct_len_u32); p += 4;
    write_u32(p, iv_len_u32); p += 4;
    write_u32(p, tag_len_u32); p += 4;
    write_u32(p, ct_len_u32); p += 4;
    write_u32(p, fname_len); p += 4;
    memcpy(p, basename, fname_len); p += fname_len;

    memcpy(p, kem_ct, kem_ct_len_u32); p += kem_ct_len_u32;
    memcpy(p, iv, iv_len_u32); p += iv_len_u32;
    memcpy(p, tag, tag_len_u32); p += tag_len_u32;
    memcpy(p, ciphertext, ct_len_u32); p += ct_len_u32;

    if (!write_file(out_bundle, out, total)) {
        fprintf(stderr, "write bundle failed\n"); free(out); free(pk); OQS_KEM_free(kem); return 1;
    }

    printf("Encrypted -> %s (bundle contains filename + kem ciphertext + iv + tag + ciphertext)\n", out_bundle);

    // cleanse & free
    OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(plain, plain_len);
    OPENSSL_cleanse(kem_ct, kem->length_ciphertext);
    OPENSSL_cleanse(ciphertext, ciphertext_len);
    free(out);
    free(ciphertext);
    free(plain);
    free(kem_ct);
    free(shared_secret);
    free(pk);
    OQS_KEM_free(kem);
    return 0;
}


// decrypt: read secret key & bundle -> parse -> decapsulate -> derive key -> decrypt -> write plaintext
// -------------------- cmd_decrypt（替换旧函数） --------------------
static int cmd_decrypt(const char *secretkey_file, const char *in_bundle, const char *out_plain) {
    size_t sk_len;
    unsigned char *sk = read_file(secretkey_file, &sk_len);
    if (!sk) { fprintf(stderr, "read secretkey failed\n"); return 1; }

    size_t bundle_len;
    unsigned char *bundle = read_file(in_bundle, &bundle_len);
    if (!bundle) { fprintf(stderr, "read bundle failed\n"); free(sk); return 1; }

    unsigned char *p = bundle;
    if (bundle_len < 4 || memcmp(p, MAGIC, 4) != 0) { fprintf(stderr, "bad bundle magic\n"); free(bundle); free(sk); return 1; }
    p += 4;
    if ((size_t)(p - bundle) + 4*5 > bundle_len) { fprintf(stderr, "bundle too short\n"); free(bundle); free(sk); return 1; }

    uint32_t kem_ct_len = read_u32(p); p += 4;
    uint32_t iv_len = read_u32(p); p += 4;
    uint32_t tag_len = read_u32(p); p += 4;
    uint32_t ct_len = read_u32(p); p += 4;
    uint32_t fname_len = read_u32(p); p += 4;

    if ((size_t)(p - bundle) + fname_len > bundle_len) { fprintf(stderr, "bundle missing filename\n"); free(bundle); free(sk); return 1; }
    char *orig_name = malloc(fname_len + 1);
    if (!orig_name) { fprintf(stderr, "malloc failed\n"); free(bundle); free(sk); return 1; }
    memcpy(orig_name, p, fname_len); orig_name[fname_len] = '\0';
    p += fname_len;

    size_t needed = kem_ct_len + iv_len + tag_len + ct_len;
    if ((size_t)(p - bundle) + needed > bundle_len) { fprintf(stderr, "bundle inconsistent lengths\n"); free(orig_name); free(bundle); free(sk); return 1; }

    unsigned char *kem_ct = malloc(kem_ct_len);
    unsigned char *iv = malloc(iv_len);
    unsigned char *tag = malloc(tag_len);
    unsigned char *ciphertext = malloc(ct_len);
    if (!kem_ct || !iv || !tag || !ciphertext) { fprintf(stderr, "malloc failed\n"); free(orig_name); free(bundle); free(sk); return 1; }

    memcpy(kem_ct, p, kem_ct_len); p += kem_ct_len;
    memcpy(iv, p, iv_len); p += iv_len;
    memcpy(tag, p, tag_len); p += tag_len;
    memcpy(ciphertext, p, ct_len); p += ct_len;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) { fprintf(stderr, "KEM new failed\n"); free(orig_name); free(bundle); free(sk); return 1; }
    if (sk_len != kem->length_secret_key) { fprintf(stderr, "secret key size mismatch\n"); free(orig_name); free(bundle); free(sk); OQS_KEM_free(kem); return 1; }

    unsigned char *shared_secret = malloc(kem->length_shared_secret);
    if (!shared_secret) { fprintf(stderr, "malloc failed\n"); free(orig_name); free(bundle); free(sk); OQS_KEM_free(kem); return 1; }

    if (OQS_KEM_decaps(kem, shared_secret, kem_ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "decaps failed\n"); free(shared_secret); free(orig_name); free(bundle); free(sk); OQS_KEM_free(kem); return 1; 
    }

    unsigned char aes_key[AES_KEYLEN];
    derive_key(shared_secret, kem->length_shared_secret, aes_key);

    unsigned char *plaintext = NULL;
    int plaintext_len = 0;
    if (!aes_gcm_decrypt(aes_key, ciphertext, (int)ct_len, iv, (int)iv_len, tag, &plaintext, &plaintext_len)) {
        fprintf(stderr, "AES-GCM decrypt failed (tag mismatch?)\n");
        free(shared_secret); free(orig_name); free(bundle); free(sk); OQS_KEM_free(kem);
        return 1;
    }

    // Decide output path:
    char out_path[1024];
    if (out_plain == NULL || out_plain[0] == '\0' || strcmp(out_plain, "-") == 0 || strcmp(out_plain, "auto") == 0) {
        // Write into same directory as bundle file
        const char *slash = strrchr(in_bundle, '/');
        #ifdef _WIN32
        const char *bs = strrchr(in_bundle, '\\');
        if (bs && (!slash || bs > slash)) slash = bs;
        #endif
        if (slash) {
            size_t dirlen = (size_t)(slash - in_bundle) + 1;
            if (dirlen + fname_len + 1 < sizeof(out_path)) {
                memcpy(out_path, in_bundle, dirlen);
                memcpy(out_path + dirlen, orig_name, fname_len);
                out_path[dirlen + fname_len] = '\0';
            } else {
                // fallback: write into current directory
                snprintf(out_path, sizeof(out_path), "%s", orig_name);
            }
        } else {
            snprintf(out_path, sizeof(out_path), "%s", orig_name);
        }
    } else {
        snprintf(out_path, sizeof(out_path), "%s", out_plain);
    }

    if (!write_file(out_path, plaintext, (size_t)plaintext_len)) {
        fprintf(stderr, "write plaintext failed\n");
        free(plaintext); free(shared_secret); free(orig_name); free(bundle); free(sk); OQS_KEM_free(kem);
        return 1;
    }

    printf("Decrypted -> %s\n", out_path);

    // cleanse & free
    OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(ciphertext, ct_len);
    OPENSSL_cleanse(kem_ct, kem_ct_len);
    free(kem_ct); free(iv); free(tag); free(ciphertext);
    free(plaintext);
    free(shared_secret);
    free(sk);
    free(bundle);
    free(orig_name);
    OQS_KEM_free(kem);
    return 0;
}



int main(int argc, char *argv[]) {
    OpenSSL_add_all_algorithms();

    // ---------- 命令行模式 ----------
    if (argc > 1) {
        if (strcmp(argv[1], "genkey") == 0) {
            if (argc != 4) {
                print_usage(argv[0]);
                return 1;
            }
            return cmd_genkey(argv[2], argv[3]);
        } else if (strcmp(argv[1], "encrypt") == 0) {
            if (argc != 5) {
                print_usage(argv[0]);
                return 1;
            }
            return cmd_encrypt(argv[2], argv[3], argv[4]);
        } else if (strcmp(argv[1], "decrypt") == 0) {
            if (argc != 5) {
                print_usage(argv[0]);
                return 1;
            }
            return cmd_decrypt(argv[2], argv[3], argv[4]);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    // ---------- 交互菜单模式 ----------
    int choice = -1;
    char pubkey_file[512], seckey_file[512];
    char input_file[512], output_file[512];
    char line[512];

    while (choice != 0) {
        printf("\n=== OQS EMR Tool ===\n");
        printf("1. Generate keypair\n");
        printf("2. Encrypt file\n");
        printf("3. Decrypt file\n");
        printf("0. Exit\n");
        printf("Enter choice: ");

        if (!fgets(line, sizeof(line), stdin)) break;
        choice = atoi(line);

        switch (choice) {
            case 1:
                printf("Enter public key output path: ");
                if (!fgets(pubkey_file, sizeof(pubkey_file), stdin)) break;
                pubkey_file[strcspn(pubkey_file, "\r\n")] = 0;
                printf("Enter secret key output path: ");
                if (!fgets(seckey_file, sizeof(seckey_file), stdin)) break;
                seckey_file[strcspn(seckey_file, "\r\n")] = 0;
                cmd_genkey(pubkey_file, seckey_file);
                break;
            case 2:
                printf("Enter public key file path: ");
                if (!fgets(pubkey_file, sizeof(pubkey_file), stdin)) break;
                pubkey_file[strcspn(pubkey_file, "\r\n")] = 0;
                printf("Enter input plaintext file path: ");
                if (!fgets(input_file, sizeof(input_file), stdin)) break;
                input_file[strcspn(input_file, "\r\n")] = 0;
                printf("Enter output encrypted bundle path: ");
                if (!fgets(output_file, sizeof(output_file), stdin)) break;
                output_file[strcspn(output_file, "\r\n")] = 0;
                cmd_encrypt(pubkey_file, input_file, output_file);
                break;
            case 3:
                printf("Enter secret key file path: ");
                if (!fgets(seckey_file, sizeof(seckey_file), stdin)) break;
                seckey_file[strcspn(seckey_file, "\r\n")] = 0;
                printf("Enter input encrypted bundle path: ");
                if (!fgets(input_file, sizeof(input_file), stdin)) break;
                input_file[strcspn(input_file, "\r\n")] = 0;
                printf("Enter output plaintext file path: ");
                if (!fgets(output_file, sizeof(output_file), stdin)) break;
                output_file[strcspn(output_file, "\r\n")] = 0;
                cmd_decrypt(seckey_file, input_file, output_file);
                break;
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }

    return 0;
}
