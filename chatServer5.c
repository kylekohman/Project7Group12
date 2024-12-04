#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <errno.h>
#include <fcntl.h>
#include "inet.h"
#include "common.h"

// Client structure to hold socket, buffers, and disconnection flag
struct client
{
	int socketNumber;
	char name[MAX];
	char toBuffer[MAX], fromBuffer[MAX];
	char *tooptr, *toiptr;
	char *froptr, *friptr;
	int flag;
	LIST_ENTRY(client)
	clients;
};

// initialize the head of the client list
LIST_HEAD(client_list_head, client);

//Function prototypes
// Set the socket to non-blocking mode
void makeSocketNonblocking(int);

// Broadcast a message to all clients except the sender
void broadcastMessageToAllClients(struct client_list_head*, const char*, struct client*);

// Handle new client connection and add to the list
void handleNewClientConnection(int, struct client_list_head*);

// Process client input message
void handleClientInput(struct client*, struct client_list_head*);

// Write data to a client socket
void writeToOneClient(struct client*);

// Clean up all clients and close the server socket
void cleanupAndRemoveAllClients(struct client_list_head*, int);

// Helper method to check if the username is already taken in the client list
int isUsernameTaken(struct client*, struct client_list_head*);



// Main server loop
int main(int argc, char **argv)
{
	int sockfd, maxfd, dir_sockfd;
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	fd_set readset, writeset;
	struct client_list_head client_list;
	struct client *client;
	socklen_t clilen;


	if(argc != 3){//ensure arugments are provided
		perror("server: Need name and port to register");
		exit(1);
	}

	// Create server socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket creation failed");
		exit(1);
	}

	// Set socket options (reuse address)
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true)) < 0)
	{
		perror("setsockopt failed");
		exit(1);
	}

	/*Parse string to an int*/
	int port; 
	if (sscanf(argv[2], "%d", &port) != 1)
	{												
		fprintf(stderr, "Failed to parse port number: %s\n", argv[2]);
		exit(1);
	}

	// Set up server address
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	// Bind to address
	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("bind failed");
		exit(1);
	}

	// Start listening for incoming connections
	listen(sockfd, 5);

	//create a socket for the directory server
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open sock stream to directory server");
		exit(1);
	}
 
	if (setsockopt(dir_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}
	/* Set directory server socket to address */
    memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
    dir_serv_addr.sin_family = AF_INET;
    dir_serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_serv_addr.sin_port = htons(SERV_TCP_PORT);

	/*Connect to the directory server*/
    if (connect(dir_sockfd, (struct dir_serv_addr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
        perror("server: can't connect to directory server");
        exit(1);
	}

	char request[MAX];
	snprintf(request, MAX, "x%s~%s", argv[1], argv[2]);
	write(dir_sockfd, request, MAX);
	// Initialize client list
	LIST_INIT(&client_list);

	for (;;)
	{
		// Initialize the descriptor sets
		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(sockfd, &readset);
		maxfd = sockfd;

		// Add clients to the read/write sets
		LIST_FOREACH(client, &client_list, clients)
		{
			//update maxfd if necessary
			if (client->socketNumber > maxfd)
			{
				maxfd = client->socketNumber;
			}

			FD_SET(client->socketNumber, &readset);
			if (client->toiptr > client->tooptr)
			{
				FD_SET(client->socketNumber, &writeset);
			}
			
		}

		// Wait for receive activity - check if bad connection
		if (select(maxfd + 1, &readset, &writeset, NULL, NULL) < 0)
		{
			if (errno == EINTR){
				continue;;
			}
			printf("\nselect failed");
			break;
		}

		// Check for new client connections
		if (FD_ISSET(sockfd, &readset))
		{
			clilen = sizeof(cli_addr);
			//make the new socket connection
			int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

			if(newsockfd < 0){
				printf("\nError in making the new socket");
				continue;
			}

			if (newsockfd >= 0)
			{
				//count the clients to determine appropriate action with new client connection
				int clientCount = 0;
				struct client *counterClient;
				LIST_FOREACH(counterClient, &client_list, clients)
				{
					clientCount++;
				}
				//if too many clients, close the connection after writing to the client to try again
				if (clientCount >= MAX_CLIENTS)
				{
					const char *serverFullMessage = "Can't join the server - Server is full.\n";
					write(newsockfd, serverFullMessage, strlen(serverFullMessage));
					close(newsockfd);
				}
				else
				{
					//set the socket to nonblocking and register a new client
					makeSocketNonblocking(newsockfd);
					handleNewClientConnection(newsockfd, &client_list);
				}
			}	
		}

		// Process input and output for each client
		LIST_FOREACH(client, &client_list, clients)
		{
			//check the write set
			if (FD_ISSET(client->socketNumber, &writeset))
			{
				//handle the writing to clients from write
				writeToOneClient(client);
			}
			//check the readset
			if (FD_ISSET(client->socketNumber, &readset))
			{
				//handle the client input from read
				handleClientInput(client, &client_list);
			}
		}
	}

	// Clean up clients and close server socket
	cleanupAndRemoveAllClients(&client_list, sockfd);
	return 0;
}

// Helper Functions

// Set the socket to non-blocking mode
// code adapted from the O'Reilly textbook. chapter 16
void makeSocketNonblocking(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
	{
		perror("fcntl get failed");
		exit(1);
	}
	flags |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, flags) < 0)
	{
		perror("fcntl set failed");
		exit(1);
	}
}

// Broadcast a message to all clients except the sender
void broadcastMessageToAllClients(struct client_list_head *head, const char *message, struct client *sender)
{
	// make a temp client that will be used as an iterator
	struct client *search;

	// This could be put to a helper method
	//  Count connected clients
	int clientCount = 0;
	LIST_FOREACH(search, head, clients)
	{
		// if there is a valid username
		// also count sockets
		if (search->name[0] != '\0' && search->socketNumber > 0)
		{
			clientCount++;
		}
	}
	// If the message is for the first client notify that they are the first to join
	if (clientCount == 1)
	{
		// make a new buffer and get the length of it so we know how to advance the pointer
		const char *firstUserJoinedMessage = "The first user has joined the chat\n";
		size_t firstUserJoinedMessageLength = strlen(firstUserJoinedMessage);
		// If there is space to receive the message (end of buffer minus data already sent)
		if (&sender->toBuffer[MAX - 1] - sender->toiptr >= firstUserJoinedMessageLength)
		{
			// copy into the clients to buffer
			memcpy(sender->toiptr, firstUserJoinedMessage, firstUserJoinedMessageLength);
			// advance the pointer
			sender->toiptr += firstUserJoinedMessageLength;
			// ensure null termination
			*(sender->toiptr) = '\0';
		}
		// No need to broadcast to others since there are none
		return;
	}

	// get the message length
	size_t messageLength = strnlen(message, MAX - 1);


	// Send the message to all clients except the sender
	LIST_FOREACH(search, head, clients)
	{
		// ensure that we don't send to ourselves and we only send to a valid user (they have a name)
		if (search != sender && search->name[0] != '\0' && search -> socketNumber > 0)
		{
			// get the size available to use
			size_t spaceAvailable = &search->toBuffer[MAX - 1] - search->toiptr;
			// make sure there is room
			if (spaceAvailable > 0)
			{
				// get our variable that will represent the amount of bytes we copy
				size_t bytesToCopy;
				
				//only copy what is available
				if(messageLength > spaceAvailable)
				{
					bytesToCopy = spaceAvailable;
				}
				//copy the full message
				else
				{
					bytesToCopy = messageLength;
				}
				//write to buffer, advance pointer, ensure null termination
				memcpy(search->toiptr, message, bytesToCopy);
				search->toiptr += bytesToCopy;
				*(search->toiptr) = '\0';
			}
		}
	}
}

// Handle new client connection and add to the list
void handleNewClientConnection(int newsockfd, struct client_list_head *client_list)
{
	//malloc the new client that is going to be added
	struct client *newClient = malloc(sizeof(struct client));
	//initialize socket, name, message buffers, and pointers
	newClient->socketNumber = newsockfd;
	memset(newClient->name, 0, MAX);
	memset(newClient->toBuffer, 0, MAX);
	memset(newClient->fromBuffer, 0, MAX);
	newClient->toiptr = newClient->tooptr = newClient->toBuffer;
	newClient->friptr = newClient->froptr = newClient->fromBuffer;

	// Add client to the list
	LIST_INSERT_HEAD(client_list, newClient, clients);
}

// Process client input message
void handleClientInput(struct client *client, struct client_list_head *client_list)
{
	//read from the client socket from the beginning of the message (fri or our current position)
	// to the available space in the buffer (MAX - fri)
	ssize_t nBytesRead = read(client->socketNumber, client->friptr, &client->fromBuffer[MAX - 1] - client->friptr);

	//an error or disconnection has occured
	if (nBytesRead <= 0)
	{
		//check EWOULDBLOCK (nonblocking error)
		if (!(nBytesRead < 0 && errno == EWOULDBLOCK))
		{
			//check to see if it's a valid client (theres a username)
			if (client->name[0] != '\0')
			{
				//at this point we need to remove the user, cleanup, and notify everyone that they've left
				char clientHasLeftBuffer[MAX];
				snprintf(clientHasLeftBuffer, MAX - 1, "%s left the chat\n", client->name);
				broadcastMessageToAllClients(client_list, clientHasLeftBuffer, client);
			}
			//cleanup
			close(client->socketNumber);
			LIST_REMOVE(client, clients);
			free(client);
		}
		return;
	}

	//find the end of the message by checking for a new line or a null terminatitor
	char *termination = NULL;
	for (size_t i = 0; i < nBytesRead; i++)
	{
		if (client->friptr[i] == '\0' || client->friptr[i] == '\n')
		{
			//update termination point when necessary
			termination = client->friptr + i;
			//if we found it we can exit
			break;
		}
	}

	//the end of message was found indicating a valid message has occured
	if (termination != NULL)
	{
		//ensure null termination
		*termination = '\0';
		//Check for the special message char - if U with an empty username, we have to assign one
		if (client->friptr[0] == 'U')
		{
			//call the helper method to check if the username is taken
			int isTaken = isUsernameTaken(client, client_list);

			//if a dupe was found
			if (isTaken == 1)
			{
				//buffer for the error message
				const char *duplicateNameMessage = "Username is already taken. Please reconnect again\n";
				//size of the error message
				size_t duplicateNameMessageLength = strlen(duplicateNameMessage);
				//copy into the clients message buffer
				memcpy(client->toiptr, duplicateNameMessage, duplicateNameMessageLength);
				//advance the pointer
				client->toiptr += duplicateNameMessageLength;
				//set their disconnection flag so they get removed later
				client->flag = 1;
			}
			//a dupe was not found
			else
			{
				//copy the name into the buffer but up to MAX - 2 becuase MAX -1 needs to be '\0'
				strncpy(client->name, client->friptr + 1, MAX - 2);
				//ensure null termination
				client->name[MAX - 1] = '\0';
				//make a buffer for the "user x has joined the chat message"
				char clientHasJoinedMessage[MAX];
				//copy message contents into the buffer
				snprintf(clientHasJoinedMessage, MAX - 1, "%s joined the chat\n", client->name);
				//broadcast that buffer to all clients
				broadcastMessageToAllClients(client_list, clientHasJoinedMessage, client);
			}
		}
		//this should be what happens most of the time since username can only be set once in the client side
		//If there is an M and the username of the client is valid, handle normal message
		else if (client->friptr[0] == 'M')
		{
			//new message buffer
			char normalMessage[MAX];
			//copy contents into the message buffer
			snprintf(normalMessage, MAX - 1, "%s: %s\n", client->name, client->friptr + 1);
			//broadcast to all clients
			broadcastMessageToAllClients(client_list, normalMessage, client);
		}

		// Reset the input buffer
		client->froptr = client->friptr = client->fromBuffer;
		memset(client->fromBuffer, 0, MAX);
	}
}

// Write data to a client socket
void writeToOneClient(struct client *client)
{
	//if there is data to send
	if (client->toiptr > client->tooptr)
	{
		//get the size of what we're attempting to write
		ssize_t nBytes = write(client->socketNumber, client->tooptr, client->toiptr - client->tooptr);
		//there was an error of some kind
		if (nBytes <= 0)
		{
			//check if that error was a nonblocking error
			if (errno != EWOULDBLOCK)
			{
				//cleanup
				close(client->socketNumber);
				LIST_REMOVE(client, clients);
				free(client);
			}
		}

		else
		{
			//advance the pointer by the number of bytes written
			client->tooptr += nBytes;
			//if the pointers are equal (ie no more data to send)
			if (client->tooptr == client->toiptr)
			{
				//if the client has a reason to disconnect remove them
				if (client->flag == 1)
				{
					//remove and cleanup
					close(client->socketNumber);
					LIST_REMOVE(client, clients);
					free(client);
				}
				//reset the buffers 
				client->tooptr = client->toiptr = client->toBuffer;
				memset(client->toBuffer, 0, MAX);
			}
		}
	}
}

// Clean up all clients and close the server socket
void cleanupAndRemoveAllClients(struct client_list_head *client_list, int sockfd)
{
	//code adapted from the linux manual pages on the LIST_ENTRY
	struct client *currentClient = LIST_FIRST(client_list);
	struct client *nextClient;

	// Traverse through the client list and clean up
	while (currentClient != NULL)
	{
		// Get the next client in the list
		nextClient = LIST_NEXT(currentClient, clients);
		// Remove from list
		LIST_REMOVE(currentClient, clients);
		// Close the client's socket and free the memory
		close(currentClient->socketNumber);
		free(currentClient);
		// Move to the next client
		currentClient = nextClient;
	}

	// close the server listening socket
	close(sockfd);
}

// Helper method to check if the username is already taken in the client list
int isUsernameTaken(struct client *client, struct client_list_head *client_list) {
    struct client *clientCheck;

    // Iterate through the client list to check for duplicate usernames
    LIST_FOREACH(clientCheck, client_list, clients) {
        // Ensure we don't compare the username with the same client, and only consider non-empty usernames
        if (clientCheck != client && strncmp(clientCheck->name, client->friptr + 1, MAX - 1) == 0) {
            // If a match is found, return 1 (username is taken)
            return 1;
        }
    }

    // If no match is found, return 0 (username is available)
    return 0;
}
