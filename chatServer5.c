#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/*Code adapted from https://www.manpagez.com/man/3/queue*/
SLIST_HEAD(slisthead, client)
head =
	SLIST_HEAD_INITIALIZER(head);

struct slisthead *headp;

// init the node structure
struct client
{
	char username[MAX], to[MAX], fr[MAX];
	char *tooptr, *froptr;
	int sockfd;
	SSL *ssl;
	SLIST_ENTRY(client)
	list;
} *np;

// function prototypes
int check_username(char[], struct client *);
struct client *remove_client(struct client *);
void encode(char *, char);
int set_nonblocking(int);
void add_to_writebuffs(char *, struct client *);

int main(int argc, char **argv)
{
	int newsockfd, maxfd, dir_sockfd, sockfd, n;
	unsigned int clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	char s[MAX];
	fd_set readset, writeset;
	int register_server = 1;
	int firstUser = 1;
	SSL_CTX *ctx, *dir_ctx;
	SSL *dir_ssl;
	printf("No seg fault :D");

	if (argc != 3)
	{ // ensure arugments are provided
		perror("server: Need name and port to register");
		exit(1);
	}

	ctx = initialize_ssl_ctx(KSU_FOOTBALL_CERT, KSU_FOOTBALL_KEY, CA_CERT);
	if (!ctx)
	{
		fprintf(stderr, "Failed to initialize SSL context\n");
		exit(1);
	}

	// Initialize OpenSSL context for directory server connection
	dir_ctx = initialize_ssl_ctx(KSU_FOOTBALL_CERT, KSU_FOOTBALL_KEY, CA_CERT); // Changed from NULL, NULL
	if (!dir_ctx)
	{
		fprintf(stderr, "Failed to initialize directory client SSL context\n");
		SSL_CTX_free(ctx);
		exit(1);
	}

	/* Create communication endpoint for chat server */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	 * Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0)
	{
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	/*Parse string to an int*/
	int port;
	if (sscanf(argv[2], "%d", &port) != 1)
	{
		fprintf(stderr, "Failed to parse port number: %s\n", argv[2]);
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("server: can't bind local address");
		exit(1);
	}

	listen(sockfd, 5);
	printf("Chat server is now listening on port %d\n", port);

	// create a socket for the directory server
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("server: can't open sock stream to directory server");
		exit(1);
	}

	/* Set directory server socket to address */
	memset((char *)&dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family = AF_INET;
	dir_serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
	dir_serv_addr.sin_port = htons(SERV_TCP_PORT);

	/*Connect to the directory server*/
	if (connect(dir_sockfd, (struct sockaddr *)&dir_serv_addr, sizeof(dir_serv_addr)) < 0)
	{
		perror("server: can't connect to directory server");
		exit(1);
	}

	// Set up SSL with directory server
	dir_ssl = SSL_new(dir_ctx);
	if (!dir_ssl)
	{
		perror("Failed to create SSL for directory connection");
		exit(1);
	}

	SSL_set_fd(dir_ssl, dir_sockfd);
	if (SSL_connect(dir_ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	fprintf(stderr, "Attempting to verify with name: %s\n", argv[1]);

	// Verify directory server certificate
	if (!verify_certificate(dir_ssl, "Directory Server"))
	{
		fprintf(stderr, "Directory server certificate verification failed\n");
		exit(1);
	}

	snprintf(s, MAX, "x%s~%s", argv[1], argv[2]);
	fprintf(stderr, "Sending registration: %s\n", s); // Add this line
	ssl_write_nb(dir_ssl, s, MAX, dir_sockfd);

	/*
		char response[MAX];
		if (ssl_read_nb(dir_ssl, response, MAX, dir_sockfd) > 0)
		{
			fprintf(stderr, "Directory server response: %s\n", response);
		}
		*/

	printf("Chat server started. Listening on port %d\n", port);
	printf("Registered with directory server as '%s' on port %d\n", argv[1], port);

	for (;;)
	{
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		FD_ZERO(&writeset);
		maxfd = sockfd;

		struct client *p;
		SLIST_FOREACH(p, &head, list)
		{
			FD_SET(p->sockfd, &readset);
			if (p->to != p->tooptr)
			{
				FD_SET(p->sockfd, &writeset);
			}
			if (p->sockfd > maxfd)
			{
				maxfd = p->sockfd;
			}
		}

		if (select(maxfd + 1, &readset, &writeset, NULL, NULL) < 0)
		{
			perror("select");
			exit(1);
		}

		if (FD_ISSET(sockfd, &readset))
		{
			clilen = sizeof(cli_addr);
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0)
			{
				perror("server: accept error");
				continue;
			}

			printf("New client connection on socket %d\n", newsockfd);

			// SSL handshake for the client
			SSL *client_ssl = SSL_new(ctx);
			if (!client_ssl)
			{
				close(newsockfd);
				continue;
			}

			SSL_set_fd(client_ssl, newsockfd);
			printf("Starting SSL handshake with client on socket %d\n", newsockfd);

			if (SSL_accept(client_ssl) <= 0)
			{
				fprintf(stderr, "SSL_accept() failed on socket %d.\n", newsockfd);
				ERR_print_errors_fp(stderr);
				fflush(stderr);
				SSL_free(client_ssl);
				close(newsockfd);
				continue;
			}

			printf("SSL handshake completed for client on socket %d\n", newsockfd);

			if (set_nonblocking(newsockfd) < 0)
			{
				SSL_free(client_ssl);
				close(newsockfd);
				continue;
			}

			struct client *new_c = malloc(sizeof(struct client));
			if (!new_c)
			{
				perror("server: failed to malloc new client");
				SSL_free(client_ssl);
				close(newsockfd);
				continue;
			}

			new_c->sockfd = newsockfd;
			new_c->ssl = client_ssl;
			memset(new_c->username, 0, MAX);
			memset(new_c->to, 0, MAX);
			memset(new_c->fr, 0, MAX);
			new_c->tooptr = new_c->to;
			new_c->froptr = new_c->fr;

			SLIST_INSERT_HEAD(&head, new_c, list);
		}

		struct client *np = SLIST_FIRST(&head);
		while (np != NULL)
		{
			char temp[MAX];
			if (FD_ISSET(np->sockfd, &readset))
			{
				ssize_t n = ssl_read_nb(np->ssl, np->froptr,
										&(np->fr[MAX]) - np->froptr,
										np->sockfd);

				if (n <= 0)
				{
					if (n < 0 && errno != EWOULDBLOCK)
					{
						perror("read error on socket");
					}
					np = remove_client(np);
					continue;
				}

				np->froptr += n;
				if (np->froptr > &(np->fr[MAX]))
				{
					np->froptr = np->fr[MAX - 1];
					np->fr[MAX - 1] = '\0';
				}
				printf("Server: Received '%s' from client socket %d\n", np->fr, np->sockfd);

				char code = np->fr[0];
				memmove(np->fr, np->fr + 1, np->froptr - (np->fr + 1));
				np->froptr--;

				switch (code)
				{
				case 'r':
					if (SLIST_NEXT(np, list) == NULL)
					{
						firstUser = 1;
					}
					printf("Server: First user status: %d\n", firstUser);

					printf("Server: Received username '%s'\n", np->fr);

					if (check_username(np->fr, np))
					{
						printf("Server: Username '%s' is unique.\n", np->username);

						if (firstUser)
						{
							snprintf(temp, MAX, "\nYou are the first user to join the chat\n");
							encode(temp, 'o');
							int len = strnlen(temp, MAX);
							if ((np->tooptr + len) < &(np->to[MAX]))
							{
								snprintf(np->tooptr, &(np->to[MAX]) - np->tooptr, "%s\0", temp);
								np->tooptr += len;
							}
							firstUser = 0;
						}
						else
						{
							snprintf(temp, MAX, "\n%s has joined the chat\n", np->username);
							encode(temp, 'o');
							add_to_writebuffs(temp, np);
						}
						np->froptr = np->fr;
					}
					else
					{
						printf("Server: Username '%s' is already taken.\n", np->fr);
						np = remove_client(np);
						continue;
					}
					break;
				case 'm':
					snprintf(temp, MAX, "%s: %s", np->username, np->fr);
					encode(temp, 'o');
					add_to_writebuffs(temp, np);
					np->froptr = np->fr;
					break;

				default:
					fprintf(stderr, "Invalid request\n");
					np->froptr = np->fr;
				}
			}

			if (FD_ISSET(np->sockfd, &writeset) &&
				(n = (&(np->to[MAX]) - np->tooptr)) > 0)
			{

				ssize_t nwrite = ssl_write_nb(np->ssl, np->to, n, np->sockfd);
				if (nwrite < 0 && errno != EWOULDBLOCK)
				{
					perror("write error on socket");
					np = remove_client(np);
				}
				else
				{
					printf("Server: Sending '%s' to client socket %d\n", temp, np->sockfd);

					np->tooptr += nwrite;
					if (&(np->to[MAX]) == np->tooptr)
					{
						np->tooptr = np->to;
					}
				}
			}

			np = SLIST_NEXT(np, list);
		}
	}

	// Cleanup (though we never reach here)
	SLIST_FOREACH(np, &head, list)
	{
		cleanup_ssl(np->ssl, NULL);
	}
	cleanup_ssl(dir_ssl, dir_ctx);
	cleanup_ssl(NULL, ctx);
	return 0;
}

// Updated to handle SSL cleanup
struct client *remove_client(struct client *cli)
{
	if (cli->ssl)
	{
		cleanup_ssl(cli->ssl, NULL);
	}
	close(cli->sockfd);
	struct client *n2 = SLIST_NEXT(cli, list);
	SLIST_REMOVE(&head, cli, client, list);
	free(cli);
	return n2;
}

// Modified to use SSL for write operations
void add_to_writebuffs(char *message, struct client *c)
{
	struct client *other_cli;
	SLIST_FOREACH(other_cli, &head, list)
	{
		int len = strnlen(message, MAX);
		if (other_cli != c && (other_cli->tooptr + len) < &(other_cli->to[MAX]))
		{
			snprintf(other_cli->tooptr, &(other_cli->to[MAX]) - other_cli->tooptr, "%s", message);
			other_cli->tooptr += len;
		}
	}
}

/// @brief Checks if a given username is unique
/// @param un the username to check
/// @param cli the client who requested the username
/// @return if the username is unique (1) or not (0)
int check_username(char un[], struct client *cli)
{
	struct client *p;
	SLIST_FOREACH(p, &head, list)
	{
		if (p != cli && strncmp(p->username, un, MAX) == 0) // does username already exist in linked list
		{
			return 0;
		}
	}
	snprintf(cli->username, MAX, "%s", un); // add their username
	cli->username[MAX - 1] = '\0';			// ensure null terminator
	return 1;
}

/// @brief Sets a given socket to be nonblocking
/// @param sock the socket to set as nonblocking
/// @return if the set was successful
int set_nonblocking(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		perror("Error setting non-blocking mode");
		return -1;
	}
	return 0;
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strnlen(str, MAX) + 1); // move string over
	str[0] = c;									  // insert character
}

// Add these SSL utility functions at the end of chatServer5.c

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

	// Change SSL_VERIFY_PEER to SSL_VERIFY_NONE
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	return ctx;
}

int verify_certificate(SSL *ssl, const char *expected_name)
{
	X509 *cert;
	char common_name[256];

	if (!ssl || !expected_name)
		return 0;

	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		fprintf(stderr, "No certificate provided\n");
		return 0;
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
							  NID_commonName,
							  common_name, sizeof(common_name));

	fprintf(stderr, "Certificate CN: '%s', Expected: '%s'\n", common_name, expected_name);

	int result = (strcasecmp(common_name, expected_name) == 0);
	fprintf(stderr, "Comparison result: %d\n", result);

	X509_free(cert);
	return result;
}

ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t len, int socket_fd)
{
	fd_set readfds;
	int result;

	while (1)
	{
		result = SSL_read(ssl, buf, len);
		if (result > 0)
			return result;

		int ssl_error = SSL_get_error(ssl, result);
		fprintf(stderr, "SSL_read() error: %d\n", ssl_error);

		if (ssl_error == SSL_ERROR_WANT_READ)
		{
			fprintf(stderr, "SSL_read(): Want read\n");
			FD_ZERO(&readfds);
			FD_SET(socket_fd, &readfds);
			select(socket_fd + 1, &readfds, NULL, NULL, NULL);
			continue;
		}
		else if (ssl_error == SSL_ERROR_SYSCALL)
		{
			perror("SSL_read() syscall error");
		}
		else if (ssl_error == SSL_ERROR_SSL)
		{
			ERR_print_errors_fp(stderr);
		}
		return (ssl_error == SSL_ERROR_ZERO_RETURN) ? 0 : -1;
	}
}

ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int socket_fd)
{
	fd_set writefds;
	int result;
	size_t total_written = 0;

	while (total_written < len)
	{
		result = SSL_write(ssl, buf + total_written, len - total_written);
		if (result > 0)
		{
			total_written += result;
			continue;
		}

		int ssl_error = SSL_get_error(ssl, result);
		if (ssl_error == SSL_ERROR_WANT_WRITE)
		{
			FD_ZERO(&writefds);
			FD_SET(socket_fd, &writefds);
			select(socket_fd + 1, NULL, &writefds, NULL, NULL);
			continue;
		}
		return -1;
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
		SSL_CTX_free(ctx);
}
