#ifndef COMMON_H
#define COMMON_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// Standard server definitions
#define MAX 300
#define MAX_CLIENTS 5

// SSL and TLS Config paths
#define CA_CERT "ca.crt"
#define DIR_CERT "directory.crt"
#define DIR_KEY "directory.key"
#define KSU_FOOTBALL_CERT "ksu_football.crt"
#define KSU_FOOTBALL_KEY "ksu_football.key"

// Function declarations for SSL utility functions
SSL_CTX *initialize_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file);
int verify_certificate(SSL *ssl, const char *expected_name);
ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t len, int socket_fd);
ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int socket_fd);
void cleanup_ssl(SSL *ssl, SSL_CTX *ctx);

#endif
