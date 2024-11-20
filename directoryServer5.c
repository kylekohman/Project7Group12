#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>

SLIST_HEAD(slisthead, server)
head =
	SLIST_HEAD_INITIALIZER(head);

struct slisthead *headp;

// init the node structure
struct server
{
	char serverName[MAX];
	int port;
	int sockfd;
	SLIST_ENTRY(server)
	list;
} *np;

int check_server_uniqueness(char *, int, int);
char *display_servers();
void encode(char *, char);
int find_server_port(char *);
struct server *find_server(int socket);

int main(int argc, char **argv)
{
	int sockfd, newsockfd, maxfd, port;
	unsigned int clilen;
	struct sockaddr_in cli_addr, serv_addr;
	char s[MAX];
	fd_set readset;

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

	FD_ZERO(&readset);		  // clear read set
	FD_SET(sockfd, &readset); // add the server
	maxfd = sockfd;			  // set max counter

	for (;;)
	{
		char temp[MAX];

		fd_set tempset = readset; // avoid manipulating readset

		memset(s, 0, MAX); // reset message

		if (select(maxfd + 1, &tempset, NULL, NULL, NULL) < 0)
		{ // select
			perror("dir_server: select error");
			exit(1);
		}

		if (FD_ISSET(sockfd, &tempset))
		{ // new connection
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0)
			{
				perror("server: accept error");
				exit(1);
			}
			//port = ntohs(cli_addr.sin_port);
			//fprintf(stderr, "%s:%d Accepted client connection from %s %d\n", __FILE__, __LINE__, inet_ntoa(cli_addr.sin_addr), port); // debug
			FD_SET(newsockfd, &readset); // add new socket to read set
			// update maxfd if necessary
			if (newsockfd > maxfd)
			{
				maxfd = newsockfd;
			}
		}
		for (int i = 0; i <= maxfd; i++)
		{
			if (i != sockfd && FD_ISSET(i, &tempset))
			{ // make sure its not the server AND inside the readset
				if (read(i, s, MAX) <= 0)
				{						 // close the connection to client
					FD_CLR(i, &readset); // remove from readset
					close(i);
					struct server *server_to_remove = find_server(i);
					if (server_to_remove != NULL)
					{
						SLIST_REMOVE(&head, server_to_remove, server, list); // remove the server from the linked list
						free(server_to_remove);								 // free the memory
					}
				}
				else
				{ // Client message
					// fprintf(stderr, "DIR SERVER RECEIVED: %s\n", s);//debug

					char code = s[0]; // remove first character

					// move message memory
					int len = strnlen(s, MAX);
					if (s != NULL && len > 0)
					{
						memmove(s, s + 1, len); // move string
						s[len - 1] = '\0';		// ensure null terminator
					}

					char temp[MAX]; // init temp string

					switch (code)
					{
					case 'x': // server attempting to connect
						parse_message(s, temp, &port);
						if (!check_server_uniqueness(temp, port, i))
						{														  // see if server exists in the linked list already
							write(i, "dServer name or port already in use", MAX); // send 'd'eclined character
							close(i);											  // close the clients connection
							FD_CLR(i, &readset);								  // remove from readset
						}
						break;
					case 'n':							// new client request to see the server option
						char *menu = display_servers(); // display server options
						write(i, menu, MAX);			// send message to client
						free(menu);						// free memory
						break;
					case 'c': // the clients 'c'hoice of server
						port = find_server_port(s);
						memset(s, 0, MAX); // reset message
						if (port == -1)
						{ // port not found
							snprintf(s, MAX, "oPlease Enter a Valid Chat Server Name\n");
						}
						else
						{
							snprintf(s, MAX, "b%d", port); // successfully found port
							FD_CLR(i, &readset);		   // remove the client from the directory server's readset
						}
						write(i, s, MAX); // send message
						break;
					default:
						snprintf(s, MAX, "Invalid request\n");
					}
				}
			}
		}
	}
}

int check_server_uniqueness(char *t, int p, int socket)
{
	SLIST_FOREACH(np, &head, list)
	{
		if ((strncmp(np->serverName, t, MAX) == 0) || np->port == p) // does username or port already exist in linked list
		{
			return 0;
		}
	}
	struct server *new_server = malloc(sizeof(struct server)); // create space for server
	strncpy(new_server->serverName, t, MAX);				   // add their topic
	new_server->serverName[MAX - 1] = '\0';					   // ensure null terminator
	new_server->port = p;									   // copy port
	new_server->sockfd = socket;							   // set socket
	SLIST_INSERT_HEAD(&head, new_server, list);				   // add to list
	return 1;												   // success
}

char *display_servers() // method for displaying active chat servers
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
			snprintf(buffer, MAX, "%d: %s - %d\n", count, np->serverName, np->port);
			strncat(display_string, buffer, MAX);
			count++;
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
		serverName[delimiter] = '\0'; // ensure null terminator
		sscanf(input + delimiter + 1, "%d", port);
	}
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strnlen(str, MAX) + 1); // move string over
	str[0] = c;									  // insert character
}

int find_server_port(char *sName)
{
	SLIST_FOREACH(np, &head, list)
	{												  // loop through list until server name matches
		if (strncmp(np->serverName, sName, MAX) == 0) // if server name matches
		{
			return np->port;
		}
	}
	return -1;
}

struct server *find_server(int socket)
{
	struct server *np;
	SLIST_FOREACH(np, &head, list)
	{
		if (np->sockfd == socket)
		{
			return np;
		}
	}
	return NULL;
}
