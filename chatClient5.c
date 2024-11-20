#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

void print_menu();
void encode(char *, char);
void connect_to_server(int *sockfd, struct sockaddr_in serv_addr, int port);

int main()
{
	char s[MAX] = {'\0'};
	fd_set readset;
	int sockfd;
	struct sockaddr_in serv_addr;
	int nread;				 /* number of characters */
	int requestUsername = 1; // flag variable
	int selectServer = 1;	 // flag variable

	// connect to the directory server
	connect_to_server(&sockfd, serv_addr, SERV_TCP_PORT);
	write(sockfd, "n", 1); // write inital message
	for (;;)
	{

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd + 1, &readset, NULL, NULL, NULL) > 0) // call select on readset
		{

			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset))
			{
				if (1 == scanf(" %[^\n]s", s))
				{					  // if characters to read
					if (selectServer) // client is requesting server choice
					{
						encode(s, 'c');
					}
					else
					{						 // client is connected to a chat server
						if (requestUsername) // if the client needs a username
						{
							encode(s, 'r');		 // encode message username 'r'equest
							requestUsername = 0; // set flag
						}
						else // if the client wants to send a message
						{
							encode(s, 'm'); // encode messsage username 'm'essage
						}
					}

					/* Send the user's message to the server */
					write(sockfd, s, MAX);
				}
				else
				{
					printf("Error reading or parsing user input\n"); // error message
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset))
			{
				if ((nread = read(sockfd, s, MAX)) <= 0)
				{			 // if the client's socket is closed
					exit(1); // exit the user if the socket is closed
				}
				else
				{					  // successful read
					char code = s[0]; // remove first character

					// move message memory
					int len = strnlen(s, MAX);
					if (s != NULL && len > 0)
					{
						memmove(s, s + 1, len); // move string
						s[len - 1] = '\0';		// ensure null terminator
					}
					switch (code)
					{
					case 'b':
						close(sockfd);	  // close connection from the directory server
						selectServer = 0; // server has been found
						int port;
						if (sscanf(s, "%d", &port) == 1)
						{												
							connect_to_server(&sockfd, serv_addr, port); // connect to chosen server
						}
						else
						{
							fprintf(stderr, "Failed to parse port number: %s\n", s);
						}
						print_menu();
						break;
					default:
						fprintf(stderr, "%s\n", s); // print the message
					}
					memset(&s, 0, MAX); // reset message memory
				}
			}
		}
	}
	close(sockfd);// close the socket
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
	memmove(str + 1, str, strnlen(str, MAX) + 1); // move string over
	str[0] = c;									  // insert character
}

void connect_to_server(int *sockfd, struct sockaddr_in serv_addr, int port)
{
	// take out the &serv_addr
	// Set up the address of the server to be contacted.
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
	serv_addr.sin_port = htons(port);

	// Create a socket (an endpoint for communication).
	if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("client: can't open stream socket");
		exit(1);
	}

	// Connect to the server.
	if (connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("client: can't connect to server");
		exit(1);
	}
}
