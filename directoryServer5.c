#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

SLIST_HEAD(slisthead, server)
head =
	SLIST_HEAD_INITIALIZER(head);

struct slisthead *headp;

SSL_CTX *ctx;

// init the node structure
struct server
{
	char serverName[MAX];
	int port;
	int sockfd;
	SSL *ssl;
	SLIST_ENTRY(server)
	list;
} *np;

int check_server_uniqueness(char *, int, int);
char *display_servers();
void encode(char *, char);
int find_server_port(char *);
struct server *find_server(int socket);
void parse_message(char *input, char *serverName, int *port);
struct server *remove_server(struct server *ser);


int main(int argc, char **argv)
{
	int sockfd, newsockfd, maxfd, port;
	unsigned int clilen;
	struct sockaddr_in cli_addr, serv_addr;
	char s[MAX];
	fd_set readset;

	// Initialize OpenSSL
	ctx = initialize_ssl_ctx(DIR_CERT, DIR_KEY, CA_CERT);
	if (!ctx)
	{
		fprintf(stderr, "Failed to initialize SSL context\n");
		exit(1);
	}

	/* Create communication endpoint */
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

	/* Bind socket to local address */
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("server: can't bind local address");
		exit(1);
	}

	listen(sockfd, 5);

	clilen = sizeof(cli_addr); // we may not need this here

	//FD_ZERO(&readset);		  // clear read set
	//FD_SET(sockfd, &readset); // add the server
	//maxfd = sockfd;			  // set max counter

	printf("Directory server started and listening...\n");

	for (;;)
	{
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		//FD_ZERO(&writeset);
		maxfd = sockfd;

		struct server *p;
		SLIST_FOREACH(p, &head, list)
		{
			FD_SET(p->sockfd, &readset);
			/*
			if (p->to != p->tooptr)
			{
				FD_SET(p->sockfd, &writeset);
			}
			*/
			if (p->sockfd > maxfd)
			{
				maxfd = p->sockfd;
			}
		}



		char temp[MAX];
		//fd_set tempset = readset;
		memset(s, 0, MAX);

		if (select(maxfd + 1, &readset, NULL, NULL, NULL) < 0)
		{
			perror("dir_server: select error");
			exit(1);
		}

		if (FD_ISSET(sockfd, &readset))
		{
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0)
			{
				perror("server: accept error");
				continue;
			}

			// Create new SSL connection
			SSL *ssl = SSL_new(ctx);
			if (!ssl)
			{
				ERR_print_errors_fp(stderr);
				close(newsockfd);
				continue;
			}

			SSL_set_fd(ssl, newsockfd);

			// Perform SSL handshake
			if (SSL_accept(ssl) <= 0)
			{
				ERR_print_errors_fp(stderr);
				SSL_free(ssl);
				close(newsockfd);
				continue;
			}
			printf("SSL Handshake completed for socket %d\n", newsockfd);

			// Create temporary server entry for the initial connection
			struct server *new_server = malloc(sizeof(struct server));
			if (!new_server)
			{
				perror("Failed to allocate memory for new server");
				SSL_free(ssl);
				close(newsockfd);
				continue;
			}

			// Initialize the new server structure
			memset(new_server->serverName, 0, MAX);
			new_server->port = -1; // Will be set when we receive the server info
			new_server->sockfd = newsockfd;
			new_server->ssl = ssl;

			// Add to the linked list
			SLIST_INSERT_HEAD(&head, new_server, list);

			FD_SET(newsockfd, &readset);
			printf("Added new connection, socket: %d\n", newsockfd);

			if (newsockfd > maxfd)
			{
				maxfd = newsockfd;
			}
		}

		struct server *current = SLIST_FIRST(&head);
		while(current != NULL)
		{
			if (FD_ISSET(current->sockfd, &readset))
			{
				//struct server *current = find_server(i);

				if (!current->ssl)
				{
					printf("Error: Invalid server or SSL connection for socket %d\n", current->sockfd);
					current = remove_server(current);
					continue;
				}

				ssize_t bytes = ssl_read_nb(current->ssl, s, MAX, current->sockfd);
				if (bytes <= 0)
				{
					cleanup_ssl(current->ssl, NULL);
					current = remove_server(current);
					continue;
				}

				char code = s[0];
				memmove(s, s + 1, strlen(s));

				switch (code)
				{
				case 'x':
				{ // server attempting to connect
					parse_message(s, temp, &port);
					fprintf(stderr, "Attempting to verify chat server certificate for: '%s'\n", temp);

					// Verify certificate matches server name
					if (!verify_certificate(current->ssl, temp))
					{
						ssl_write_nb(current->ssl, "dCertificate name mismatch", MAX, current->sockfd);
						cleanup_ssl(current->ssl, NULL);
						current = remove_server(current);
						continue;
					}

					if (!check_server_uniqueness(temp, port, current->sockfd))
					{
						ssl_write_nb(current->ssl, "dServer name or port already in use", MAX, current->sockfd);
						cleanup_ssl(current->ssl, NULL);
						current = remove_server(current);
					}
					break;
				}
				case 'n':
				{
					char *menu = display_servers();
					ssl_write_nb(current->ssl, menu, MAX, current->sockfd);
					free(menu);
					break;
				}
				case 'c':
				{
					printf("Directory received request for server name: '%s'\n", s);
					port = find_server_port(s);
					memset(s, 0, MAX);

					if (port == -1)
					{
						snprintf(s, MAX, "oPlease Enter a Valid Chat Server Name\n");
					}
					else
					{
						snprintf(s, MAX, "b%d", port);
						//FD_CLR(current->sockfd, &readset);
					}
					printf("Directory response: '%s'\n", s); // Log what is sent back
					ssl_write_nb(current->ssl, s, MAX, current->sockfd);
					break;
				}

				default:
					snprintf(s, MAX, "Invalid request\n");
					ssl_write_nb(current->ssl, s, MAX, current->sockfd);
				}//end of switch case
			}//end readset check
			current = SLIST_NEXT(current, list);
		}//end while
	}//end of main loop

	cleanup_ssl(NULL, ctx);
	close(sockfd);
	return 0;
}//end of main

// Modified to store SSL connection
int check_server_uniqueness(char *t, int p, int socket)
{
	// First check if any other server has this name or port
	SLIST_FOREACH(np, &head, list)
	{
		if (np->sockfd != socket && // Skip checking against self
			(strncmp(np->serverName, t, MAX) == 0 || np->port == p))
		{
			return 0;
		}
	}

	// Find our temporary server entry and update it
	SLIST_FOREACH(np, &head, list)
	{
		if (np->sockfd == socket)
		{
			strncpy(np->serverName, t, MAX);
			np->serverName[MAX - 1] = '\0';
			np->port = p;
			return 1;
		}
	}

	return 0; // Should never reach here if properly initialized
}

char *display_servers()
{
	char *display_string = malloc(MAX * 5);
	char buffer[MAX];
	int count = 1;
	snprintf(display_string, MAX, "=================================\nSERVER LIST: Number: Name - Port\nEnter Server Name to Join\n=================================\n");

	if (SLIST_EMPTY(&head))
	{
		strncat(display_string, "No Chat Servers Currently Online\n", MAX);
	}
	else
	{
		SLIST_FOREACH(np, &head, list)
		{
			if (np->port != -1)
			{ // Only display fully initialized servers
				snprintf(buffer, MAX, "%d: %s - %d\n", count, np->serverName, np->port);
				strncat(display_string, buffer, MAX);
				count++;
			}
		}
	}

	strncat(display_string, "=================================\n", MAX);
	return display_string;
}

void parse_message(char *input, char *serverName, int *port)
{
	int delimiter = -1;
	for (int i = 0; i < strnlen(input, MAX); i++)
	{
		if (input[i] == '~')
		{
			delimiter = i;
			break;
		}
	}
	if (delimiter >= 0)
	{
		strncpy(serverName, input, delimiter);
		serverName[delimiter] = '\0';
		sscanf(input + delimiter + 1, "%d", port);
	}
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strnlen(str, MAX) + 1);
	str[0] = c;
}

int find_server_port(char *sName)
{
	printf("Searching for server name: '%s'\n", sName);
	SLIST_FOREACH(np, &head, list)
	{
		printf("Comparing '%s' with registered server '%s'\n", sName, np->serverName);
		if (strncmp(np->serverName, sName, MAX) == 0) // Case-sensitive comparison
		{
			printf("Match found: Port %d\n", np->port);
			return np->port;
		}
	}
	printf("No match found for: '%s'\n", sName);
	return -1;
}

struct server *find_server(int socket)
{
	SLIST_FOREACH(np, &head, list)
	{
		if (np->sockfd == socket)
		{
			return np;
		}
	}
	return NULL;
}

// SSL utility functions remain unchanged
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
	X509 *cert;
	char common_name[256];

	fprintf(stderr, "Directory Server verifying certificate for expected name: '%s'\n", expected_name);

	if (!ssl || !expected_name)
	{
		fprintf(stderr, "SSL or expected_name is NULL\n");
		return 0;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		fprintf(stderr, "No certificate provided by peer\n");
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
		if (ssl_error == SSL_ERROR_WANT_READ)
		{
			FD_ZERO(&readfds);
			FD_SET(socket_fd, &readfds);
			select(socket_fd + 1, &readfds, NULL, NULL, NULL);
			continue;
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

struct server *remove_server(struct server *ser)
{
	close(ser->sockfd);
	//FD_CLR(ser->sockfd, &readset);//remove later
	struct server *n2 = SLIST_NEXT(ser, list);
	SLIST_REMOVE(&head, ser, server, list);
	free(ser);
	return n2;
}