#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"	// Ensure this header file contains necessary definitions
#include "common.h" // Ensure this header file contains necessary definitions
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h> // For fcntl()

void print_menu();
void encode(char *, char);
void connect_to_server(int *sockfd, SSL **ssl, SSL_CTX *ctx,
					   struct sockaddr_in serv_addr, int port, const char *expected_name);

// Function prototypes
SSL_CTX *initialize_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file);
int verify_certificate(SSL *ssl, const char *expected_name);
ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t len, int socket_fd);
ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int socket_fd);
void cleanup_ssl(SSL *ssl, SSL_CTX *ctx);

int main()
{
	char s[MAX] = {'\0'};
	char serverName[MAX] = {'\0'};
	fd_set readset;
	int sockfd = -1;
	struct sockaddr_in serv_addr;
	int requestUsername = 1;
	int selectServer = 1;
	SSL_CTX *ctx;
	SSL *ssl;

	ctx = initialize_ssl_ctx(NULL, NULL, CA_CERT);
	if (!ctx)
	{
		fprintf(stderr, "Failed to initialize SSL context\n");
		exit(1);
	}

	connect_to_server(&sockfd, &ssl, ctx, serv_addr, SERV_TCP_PORT, "Directory Server");

	strcpy(s, "n"); // Send 'n' as the initial message
	ssize_t nwritten = ssl_write_nb(ssl, s, strlen(s), sockfd);

	for (;;)
	{
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		if (sockfd > 0)
		{
			FD_SET(sockfd, &readset);
		}
		else
		{
			fprintf(stderr, "Invalid sockfd: %d\n", sockfd);
			exit(1);
		}

		int nfds = (sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO) + 1;

		int select_ret = select(nfds, &readset, NULL, NULL, NULL);
		if (select_ret > 0)
		{
			if (FD_ISSET(STDIN_FILENO, &readset))
			{
				if (fgets(s, sizeof(s), stdin) != NULL)
				{
					s[strcspn(s, "\n")] = '\0'; // Remove the newline character from input

					if (selectServer)
					{
						strncpy(serverName, s, MAX);
						serverName[MAX - 1] = '\0';
						encode(s, 'c');
						nwritten = ssl_write_nb(ssl, s, strlen(s), sockfd);
					}
					else
					{
						if (requestUsername)
						{
							encode(s, 'r');
							nwritten = ssl_write_nb(ssl, s, strlen(s), sockfd);
							requestUsername = 0;
						}
						else
						{
							encode(s, 'm');
							nwritten = ssl_write_nb(ssl, s, strlen(s), sockfd);
						}
					}
				}
				else
				{
					perror("Error reading user input");
				}
			}

			if (FD_ISSET(sockfd, &readset))
			{
				ssize_t nread = ssl_read_nb(ssl, s, sizeof(s) - 1, sockfd);
				if (nread < 0)
				{
					// Error or connection closed
					fprintf(stderr, "ERROR: Failed to read from server or connection closed.\n");
					cleanup_ssl(ssl, NULL);
					close(sockfd);
					exit(1);
				}
				else if (nread == 0)
				{
					// No data available; continue to next iteration
					continue;
				}
				else
				{
					// Data received; process it
					s[nread] = '\0'; // Null-terminate the received data
					char code = s[0];
					int len = strlen(s);
					if (len > 1)
					{
						memmove(s, s + 1, len);
						s[len - 1] = '\0';
					}
					else
					{
						s[0] = '\0';
					}

					switch (code)
					{
					case 'b':
					{
						cleanup_ssl(ssl, NULL);
						close(sockfd);
						selectServer = 0;

						int port;
						if (sscanf(s, "%d", &port) == 1)
						{
							connect_to_server(&sockfd, &ssl, ctx, serv_addr, port, serverName);
						}
						else
						{
							fprintf(stderr, "Failed to parse chat server details: %s\n", s);
							cleanup_ssl(NULL, ctx);
							exit(1);
						}
						print_menu();
						requestUsername = 1; // Ensure we request the username after connecting to chat server

						break;
					}

					default:
						fprintf(stderr, "%s\n", s);
					}
					memset(&s, 0, sizeof(s));
				}
			}
		}
		else if (select_ret == 0)
		{
			// Without a timeout, select_ret == 0 should not occur
		}
		else
		{
			perror("select() failed");
			exit(1);
		}
	}
}

void connect_to_server(int *sockfd, SSL **ssl, SSL_CTX *ctx, struct sockaddr_in serv_addr, int port, const char *expected_name)
{
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
	serv_addr.sin_port = htons(port);

	if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("client: can't open stream socket");
		exit(1);
	}

	// Set socket to non-blocking mode
	int flags = fcntl(*sockfd, F_GETFL, 0);
	if (flags == -1)
	{
		perror("fcntl F_GETFL failed");
		close(*sockfd);
		exit(1);
	}
	if (fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		perror("fcntl F_SETFL failed");
		close(*sockfd);
		exit(1);
	}

	// Attempt to connect (non-blocking connect)
	int connect_ret = connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (connect_ret < 0)
	{
		if (errno != EINPROGRESS)
		{
			perror("client: can't connect to server");
			close(*sockfd);
			exit(1);
		}
		else
		{
			// Use select() to wait until the socket is writable
			fd_set writefds;
			FD_ZERO(&writefds);
			FD_SET(*sockfd, &writefds);
			if (select(*sockfd + 1, NULL, &writefds, NULL, NULL) < 0)
			{
				close(*sockfd);
				exit(1);
			}
			else if (FD_ISSET(*sockfd, &writefds))
			{
				int so_error;
				socklen_t len = sizeof(so_error);
				getsockopt(*sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
				if (so_error != 0)
				{
					fprintf(stderr, "client: connect failed with error %d\n", so_error);
					close(*sockfd);
					exit(1);
				}
			}
			else
			{
				fprintf(stderr, "client: connect timed out\n");
				close(*sockfd);
				exit(1);
			}
		}
	}

	// Create new SSL connection
	*ssl = SSL_new(ctx);
	if (!*ssl)
	{
		perror("Failed to create SSL");
		close(*sockfd);
		exit(1);
	}

	SSL_set_fd(*ssl, *sockfd);

	// Start SSL handshake
	int ssl_ret;
	while ((ssl_ret = SSL_connect(*ssl)) != 1)
	{
		int ssl_error = SSL_get_error(*ssl, ssl_ret);
		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
		{
			// Use select() to wait for the socket to be ready
			fd_set readfds, writefds;
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			if (ssl_error == SSL_ERROR_WANT_READ)
				FD_SET(*sockfd, &readfds);
			else if (ssl_error == SSL_ERROR_WANT_WRITE)
				FD_SET(*sockfd, &writefds);

			if (select(*sockfd + 1, &readfds, &writefds, NULL, NULL) < 0)
			{
				perror("select() failed during SSL_connect");
				SSL_free(*ssl);
				close(*sockfd);
				exit(1);
			}
			continue;
		}
		else
		{
			fprintf(stderr, "SSL_connect() failed.\n");
			ERR_print_errors_fp(stderr);
			SSL_free(*ssl);
			close(*sockfd);
			exit(1);
		}
	}

	// Verify server certificate
	if (!verify_certificate(*ssl, expected_name))
	{
		fprintf(stderr, "Server certificate verification failed\n");
		cleanup_ssl(*ssl, NULL);
		close(*sockfd);
		exit(1);
	}
}

void print_menu()
{
	fprintf(stderr, "=================================\n");
	fprintf(stderr, "Welcome to the Chat Room! \n\n");
	fprintf(stderr, "MESSAGE LIMIT: 100 Characters\n");
	fprintf(stderr, "=================================\n");
	fprintf(stderr, "Please Enter a Username: ");
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strlen(str) + 1); // move string over
	str[0] = c;								// insert character
}

SSL_CTX *initialize_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file)
{
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_method());
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL))
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (cert_file && key_file)
	{
		if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
			SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ||
			!SSL_CTX_check_private_key(ctx))
		{
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	return ctx;
}

int verify_certificate(SSL *ssl, const char *expected_name)
{
	X509 *cert = NULL;
	X509_NAME *subject = NULL;
	char common_name[256] = {0};
	int result = 0;

	if (!ssl || !expected_name)
	{
		return 0;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		fprintf(stderr, "No certificate presented by the server.\n");
		return 0;
	}

	subject = X509_get_subject_name(cert);
	if (!subject)
	{
		fprintf(stderr, "Failed to get subject from certificate.\n");
		X509_free(cert);
		return 0;
	}

	if (X509_NAME_get_text_by_NID(subject, NID_commonName, common_name, sizeof(common_name)) <= 0)
	{
		fprintf(stderr, "Failed to get common name from certificate.\n");
		X509_free(cert);
		return 0;
	}

	common_name[sizeof(common_name) - 1] = '\0'; // Ensure null termination

	result = (strcasecmp(common_name, expected_name) == 0);

	X509_free(cert);
	return result;
}

ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t len, int socket_fd)
{
	int result = SSL_read(ssl, buf, len);
	if (result > 0)
	{
		return result;
	}

	int ssl_error = SSL_get_error(ssl, result);
	if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
	{
		return 0; // No data available, non-blocking mode
	}
	else if (ssl_error == SSL_ERROR_ZERO_RETURN)
	{
		return -1; // Connection closed
	}
	else
	{
		// Other error
		ERR_print_errors_fp(stderr);
		return -1;
	}
}

ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int socket_fd)
{
	size_t total_written = 0;

	while (total_written < len)
	{
		int result = SSL_write(ssl, buf + total_written, len - total_written);
		if (result > 0)
		{
			total_written += result;
		}
		else
		{
			int ssl_error = SSL_get_error(ssl, result);
			if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ)
			{
				// Wait for the socket to be ready
				fd_set writefds;
				FD_ZERO(&writefds);
				FD_SET(socket_fd, &writefds);
				select(socket_fd + 1, NULL, &writefds, NULL, NULL);
				continue;
			}
			else
			{
				ERR_print_errors_fp(stderr);
				return -1;
			}
		}
	}
	return total_written;
}

void cleanup_ssl(SSL *ssl, SSL_CTX *ctx)
{
	if (ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ctx)
	{
		SSL_CTX_free(ctx);
	}
}
