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
	char Username[MAX];
	int sockfd;
	SLIST_ENTRY(client) list;
} *np;

//function prototypes
int check_username(char *, struct client*);
void broadcast(int, char*);
struct client* remove_client(struct client*);
void encode(char *, char );


int main(int argc, char **argv)
{
	int				newsockfd, maxfd, dir_sockfd, sockfd;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	char				s[MAX];
	fd_set readset;
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
	//FD_ZERO(&readset);
	//FD_SET(dir_sockfd, &readset);
	//maxfd = dir_sockfd;

	//add listening socket of sub server to readset
	//FD_SET(sockfd, &readset);
	
	for (;;) {
		FD_ZERO(&readset);//clear read set
		FD_SET(sockfd, &readset);//add the server
		//FD_SET(dir_sockfd, &readset);
		maxfd = sockfd;
		//if (sockfd > maxfd) {
   		//maxfd = sockfd;
		//}	

		struct client* p;
		SLIST_FOREACH(p, &head, list){
			FD_SET(p->sockfd, &readset);
			if (p->sockfd > maxfd) 
			{
				maxfd = p->sockfd;//update maxfd
			}
		}

		if (select(maxfd + 1, &readset, NULL, NULL, NULL) < 0) {//select
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

			//add the client
			struct client *new_c = (struct client *)malloc(sizeof(struct client));
			if(!new_c){//check malloc success
				perror("server: failed to malloc new clinet");
				close(sockfd);
				continue;
			} 
			new_c->sockfd = newsockfd; //set the new socket
			memset(new_c->Username, 0, MAX);
			snprintf(new_c->Username, MAX, "\0");//init the username to null term
			
			FD_SET(newsockfd, &readset);//add new socket to read set
			//update maxfd if necessary
			if (newsockfd > maxfd) {
				maxfd = newsockfd;
			}
			SLIST_INSERT_HEAD(&head, new_c, list); //insert client into the linked list
		}

		struct client* cli_ptr = SLIST_FIRST(&head);

		while(cli_ptr != NULL) {
			if (FD_ISSET(cli_ptr->sockfd, &readset)) {//make sure its not the server AND inside the readset
				if (read(cli_ptr->sockfd, s, MAX) <= 0) {//connection has been closed
					close(cli_ptr->sockfd);//close
					FD_CLR(cli_ptr->sockfd, &readset);//remove from readset

					/*Find the user who quit*/
					//char un[MAX];

					//find_username(cli_ptr->sockfd, un); //can remove this

					snprintf(s, MAX, "\n%s has left the chat\n", cli_ptr->Username);//attach the message

					cli_ptr = remove_client(cli_ptr);//remove client from the linked list
				} 
				else {//Client message
					fprintf(stderr, "SERVER RECEIVED: %s\n", s);//debug

					char code = s[0];//remove first character

					//move message memory
					int len = strnlen(s, MAX); 
					if (s != NULL && len > 0)
					{
						memmove(s, s+1, len);//move string 
						s[len - 1] = '\0';//ensure null terminator
					}

					char temp[MAX];//init temp string

					switch (code) {
						case 'd'://declined by the directory server
							fprintf(stderr, MAX, "%s\n");
							exit(1);//exit the server
							break;//probably unnecessary
						case 'r'://request a username
							if(SLIST_NEXT(cli_ptr, list) == NULL){//check if the user who joins is the first user
								firstUser = 1;
							}
							if (check_username(s, cli_ptr)) {//see if username exists in the linked list already

								//strncpy(temp, s, MAX);//copy the username into temp to possible use in message

								if(firstUser){//tell the user they are the first to join
									snprintf(temp, MAX, "\nYou are the first user to join the chat\n");//first user message
									encode(temp, 'o');//endcode for standard message
									write(cli_ptr->sockfd, temp, MAX);//send the message to only the first client
									firstUser = 0;//set flag
								}
								else{//other users join
									snprintf(s, MAX, "\n%s has joined the chat\n", temp);
								}
							}
							else {//username is currently in chat
								snprintf(s, MAX, "Username Already Exists\n");
								encode(s, 'o');//endcode for standard message
								write(cli_ptr->sockfd, s, MAX);//only send to the client trying to log in
								close(cli_ptr->sockfd);//close the clients connection
								FD_CLR(cli_ptr->sockfd, &readset);//remove from readset
								cli_ptr = remove_client(cli_ptr);//remove the client from the linked list
							}
							break;
						case 'm'://message from client
							//char uname[MAX];
							//find_username(cli_ptr->sockfd, uname);//find user who sent the message
							snprintf(temp, MAX, "%s: %s", cli_ptr->Username, s);
							//strncpy(s, temp, MAX);
							snprintf(s, MAX, "%s", temp);
							break;
						default:
							snprintf(s, MAX, "Invalid request\n");
					}
				}
				//encode(s, 'o');//endcode for standard message

				broadcast(cli_ptr->sockfd, s);//broadcast message to call clients
			}//end of readset check
			struct client* np2 = SLIST_NEXT(np, list);
			np = np2;
			fprintf(stderr, "next client\n");
		}//end of while loop
	}//end of main loop
}//end of main

void broadcast(int socket, char* s)
{
	SLIST_FOREACH(np, &head, list)
	{
		if(np->sockfd != socket){
			if(write(np->sockfd, s, MAX) < 0)
			{
				perror("write error");
			}
		}
	}
}

/// @brief Checks if a given username is unique
/// @param un the username to check
/// @param cli the client who requested the username
/// @return if the username is unique (1) or not (0)
int check_username(char un[], struct client* cli)
{
	struct client* p;
	SLIST_FOREACH(p, &head, list)
	{
		if(p != cli && strncmp(p->Username, un, MAX) == 0)//does username already exist in linked list
		{
			return 0;
		}
	}
	snprintf(cli->Username, MAX, "%s", un);//add their username
	cli->Username[MAX - 1] = '\0';//ensure null terminator
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

void encode(char *str, char c)
{
	char temp[MAX];
	snprintf(temp, MAX, "%c%s", c, str);
	snprintf(str, MAX, temp);
}
