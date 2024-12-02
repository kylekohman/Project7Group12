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

/*Code adapted from https://www.manpagez.com/man/3/queue*/
SLIST_HEAD(slisthead, client) head =
         SLIST_HEAD_INITIALIZER(head);

struct slisthead *headp;

//init the node structure
struct client {
	char username[MAX], to[MAX], fr[MAX];
	char *tooptr, *froptr;
	int sockfd;
	SLIST_ENTRY(client) list;
} *np;

//function prototypes
int check_username(char[], struct client*);
struct client* remove_client(struct client*);
void encode(char *, char );
int set_nonblocking(int);
void add_to_writebuffs(char*, struct client*);

int main(int argc, char **argv)
{
	int				newsockfd, maxfd, dir_sockfd, sockfd, n;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	char				s[MAX];
	fd_set readset, writeset;
	int register_server = 1;
	int firstUser = 1;
	
	
	if(argc != 3){//ensure arugments are provided
		perror("server: Need name and port to register");
		exit(1);
	}

	/* Create communication endpoint for chat server */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
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
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(port);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}

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

	snprintf(s, MAX, "x%s~%s", argv[1], argv[2]);
	write(dir_sockfd, s, MAX);//send topic and port to directory server

	//ADD dir server to readset
	FD_ZERO(&readset);
	FD_SET(dir_sockfd, &readset);
	maxfd = dir_sockfd;

	//add listening socket of sub server to readset
	FD_SET(sockfd, &readset);
	if (sockfd > maxfd) {
   		maxfd = sockfd;
	}
	
	for (;;) {

		FD_ZERO(&readset);//clear read set
		FD_SET(sockfd, &readset);//add the server
		FD_ZERO(&writeset);//clear the write set
		maxfd = sockfd;// init maxfd

		//add fd to the correct sets
		struct client* p;
		SLIST_FOREACH(p, &head, list){
			FD_SET(p->sockfd, &readset);
			if (p->to != p->tooptr) { // Add data recived != data sent
				FD_SET(p->sockfd, &writeset);
			}
			if (p->sockfd > maxfd) 
			{
				maxfd = p->sockfd;//update maxfd
			}
		}

		if (select(maxfd + 1, &readset, &writeset, NULL, NULL) < 0) {//select
			perror("select");
			exit(1);
		}

		/* Accept a new connection request */
		if (FD_ISSET(sockfd, &readset)) {//new connection
			clilen = sizeof(cli_addr);
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0) {
				perror("server: accept error");
				continue;
			}

			//set server to nonblocking
			if(set_nonblocking(newsockfd) < 0){
				close(newsockfd);
				continue;
			}
			
			//ADD CLIENT TO THE LIST
			struct client *new_c = (struct client *)malloc(sizeof(struct client));
			if(!new_c){//check malloc success
				perror("server: failed to malloc new clinet");
				close(sockfd); //close if failure
				continue;
			} 
			new_c->sockfd = newsockfd; //set the new socket

			//ensure username and buffers are set clean
		    memset(new_c->username, 0, MAX);
			snprintf(new_c->username, MAX, "\0");//init the username to null term
			memset(new_c->to, 0, MAX);
            memset(new_c->fr, 0, MAX);

			// Initialize buffer pointers 
			new_c->tooptr = new_c->to; 
			new_c->froptr = new_c->fr; 

			// Insert the new client into the linked list 
			SLIST_INSERT_HEAD(&head, new_c, list);
    	}

		//LOOP THROUGH CLIENTS
		struct client* np = SLIST_FIRST(&head);
		while(np != NULL) {
			char temp[MAX];
			if (FD_ISSET(np->sockfd, &readset)) {//make sure its not the server AND inside the readset
				if ((n = read(np->sockfd, np->froptr, &(np->fr[MAX]) - np->froptr)) < 0) {//connection has been closed
					if (errno != EWOULDBLOCK) { 
						perror("read error on socket");
						np = remove_client(np);
					}
				}
				else if(n == 0)//client leaves
				{
					snprintf(temp, MAX, "\n%s has left the chat\n", np->username);//attach the message
					add_to_writebuffs(temp, np);
					np = remove_client(np);//remove client from the linked list
					continue;
				} 
				else {//Client message
					//fprintf(stderr, "SERVER RECEIVED: %s\n", s);//debug
					np->froptr += n; // Move forward the progress pointer 
					
					//possibly remove these checks
					if (np->froptr > &(np->fr[MAX])) { // If the progress pointer reaches the end of the buffer, reset it 
						np->froptr = np->fr[MAX - 1];
						np->fr[MAX - 1] = '\0';
					}

					char code = np->fr[0];//remove first character

					memmove(np->fr, np->fr + 1, np->froptr - (np->fr + 1));//remove the encoding from the message
					np->froptr--;//need to check memory here

					char temp[MAX];//init temp string

					switch (code) {
						case 'd'://declined by the directory server
							fprintf(stderr, MAX, "%s\n");
							exit(1);//exit the server
							break;//probably unnecessary
						case 'r'://request a username
							if (SLIST_NEXT(np, list) == NULL){//check if the user who joins is the first user
								firstUser = 1;
							}
							if (check_username(np->fr, np)) {//see if username exists in the linked list already

								if(firstUser){//tell the user they are the first to join
									snprintf(temp, MAX, "\nYou are the first user to join the chat\n");//first user message
									encode(temp, 'o');//endcode for standard message
									//ADD TO CLIENTS WRITE BUFF
									int len = strnlen(temp, MAX);
									
									if((np->tooptr + len) < &(np->to[MAX])){//check if there is room in the buffer
										snprintf(np->tooptr, &(np->to[MAX]) - np->tooptr, "%s\0", temp);//add to buffer
										np->tooptr += len;//update the pointer
									}

									firstUser = 0;//set flag
								}
								else{//other users join
									snprintf(temp, MAX, "\n%s has joined the chat\n", np->username);
									encode(temp, 'o');//endcode for standard message
									add_to_writebuffs(temp, np);
									np->froptr = np->fr;
								}
							}
							else {//username is currently in chat
								fprintf(stderr, "Username Already Exists\n");//print to std err as no client needs to be notified
								np = remove_client(np);					
							}
							break;
						case 'm'://message from client
							snprintf(temp, MAX, "%s: %s", np->username, np->fr);
							encode(temp, 'o');//endcode for standard message
							add_to_writebuffs(temp, np);
							np->froptr = np->fr;
							break;
						default:
							fprintf(stderr, "Invalid request\n");
					}
					np->froptr = np->fr;//reset the pointers
				}//end of else
				/*
				encode(s, 'o');//endcode for standard message
				struct client* cli;
				SLIST_FOREACH(cli, &head, list){//braodcast to everyone but the sender
					if(cli->sockfd != np->sockfd){
						write(cli->sockfd, s, MAX);
					}					
				}
				*/
			}//end readset

			//Writeset check
			if(FD_ISSET(np->sockfd, &writeset) && (n = (&(np->to[MAX]) - np->tooptr)) > 0){
				ssize_t nwrite = write(np->sockfd, np->to, n);
				if (nwrite < 0 && errno != EWOULDBLOCK) { 
					perror("write error on socket");
					np = remove_client(np);
				}
				else { 
					np->tooptr += nwrite;
					if (&(np->to[MAX]) == np->tooptr) { // All data sent 
						np->tooptr = np->to; 
					}
				}
			}//end of writeset check

			struct client* np2 = SLIST_NEXT(np, list);
			np = np2;
		}// end of while loop
	}//end of main loop
}//end of main

/// @brief Checks if a given username is unique
/// @param un the username to check
/// @param cli the client who requested the username
/// @return if the username is unique (1) or not (0)
int check_username(char un[], struct client* cli)
{
	struct client* p;
	SLIST_FOREACH(p, &head, list)
	{
		if(p != cli && strncmp(p->username, un, MAX) == 0)//does username already exist in linked list
		{
			return 0;
		}
	}
	snprintf(cli->username, MAX, "%s", un);//add their username
	cli->username[MAX - 1] = '\0';//ensure null terminator
	return 1;
}

/// @brief removes a client from the linked list
/// @param cli the client to remove
struct client* remove_client(struct client* cli)
{
	close(cli->sockfd);
	struct client* n2 = SLIST_NEXT(cli, list);
	SLIST_REMOVE(&head, cli, client, list);//remove client from linked list CHECK
	free(cli);
	return n2;
}

/// @brief Sets a given socket to be nonblocking
/// @param sock the socket to set as nonblocking
/// @return if the set was successful
int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting non-blocking mode");
        return -1;
    }
    return 0;
}

/// @brief Adds a message to all besides the source client's writebuff
/// @param message the message to add to the buffs
/// @param c the source client
void add_to_writebuffs(char* message, struct client* c){
	struct client* other_cli;
	SLIST_FOREACH(other_cli, &head, list){
		int len = strnlen(message, MAX);
		//check if there is room in the buffer
		if(other_cli != c && (other_cli->tooptr + len) < &(other_cli->to[MAX])){
			snprintf(other_cli->tooptr, &(other_cli->to[MAX]) - other_cli->tooptr, "%s", message);//add to buffer
			other_cli->tooptr += len;//update the pointer
		}
	}
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strnlen(str, MAX) + 1);//move string over
	str[0] = c;//insert character
}
