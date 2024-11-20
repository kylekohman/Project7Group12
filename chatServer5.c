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
int check_username(char[], int);
void find_username(int, char*);
void remove_client(int);
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
	FD_ZERO(&readset);
	FD_SET(dir_sockfd, &readset);
	maxfd = dir_sockfd;

	//add listening socket of sub server to readset
	FD_SET(sockfd, &readset);
	if (sockfd > maxfd) {
   		maxfd = sockfd;
	}
	
	for (;;) {

		fd_set tempset = readset;//avoid manipulating readset

		if (select(maxfd + 1, &tempset, NULL, NULL, NULL) < 0) {//select
			perror("select");
			exit(1);
		}

		/* Accept a new connection request */
		if (FD_ISSET(sockfd, &tempset)) {//new connection
			clilen = sizeof(cli_addr);
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0) {
				perror("server: accept error");
				exit(1);
			}
			FD_SET(newsockfd, &readset);//add new socket to read set
			//update maxfd if necessary
			if (newsockfd > maxfd) {
				maxfd = newsockfd;
			}
    	}

		for (int i = 0; i <= maxfd; i++) {
			if (i != sockfd && FD_ISSET(i, &tempset)) {//make sure its not the server AND inside the readset
				if (read(i, s, MAX) <= 0) {//connection has been closed
					close(i);//close
					FD_CLR(i, &readset);//remove from readset

					/*Find the user who quit*/
					char un[MAX];
					find_username(i, un);

					snprintf(s, MAX, "\n%s has left the chat\n", un);//attach the message

					remove_client(i);//remove client from the linked list
				} 
				else {//Client message
					//fprintf(stderr, "SERVER RECEIVED: %s\n", s);//debug

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
							if(SLIST_EMPTY(&head)){//check if the user who joins is the first user
								firstUser = 1;
							}
							if (check_username(s, i)) {//see if username exists in the linked list already

								strncpy(temp, s, MAX);//copy the username into temp to possible use in message

								if(firstUser){//tell the user they are the first to join
									snprintf(s, MAX, "\nYou are the first user to join the chat\n");//first user message
									encode(s, 'o');//endcode for standard message
									write(i, s, MAX);//send the message to only the first client
									firstUser = 0;//set flag
								}
								else{//other users join
									snprintf(s, MAX, "\n%s has joined the chat\n", temp);
								}
							}
							else {//username is currently in chat
								snprintf(s, MAX, "Username Already Exists\n");
								encode(s, 'o');//endcode for standard message
								write(i, s, MAX);//only send to the client trying to log in
								close(i);//close the clients connection
								FD_CLR(i, &readset);//remove from readset
								remove_client(i);//remove the client from the linked list
							}
							break;
						case 'm'://message from client
							char uname[MAX];
							find_username(i, uname);//find user who sent the message
							snprintf(temp, MAX, "%s: %s", uname, s);
							strncpy(s, temp, MAX);
							break;
						default:
							snprintf(s, MAX, "Invalid request\n");
					}
				}
				encode(s, 'o');//endcode for standard message
				SLIST_FOREACH(np, &head, list){//braodcast to everyone but the sender
					if(np->sockfd != i){
						write(np->sockfd, s, MAX);
					}					
				}
			}
		}
	}
}

void find_username(int sockfd2, char* un)
{
	SLIST_FOREACH(np, &head, list){//loop through list until socket matches
		if(np->sockfd == sockfd2){
			strncpy(un, np->Username, MAX);//copy the username into un
			break;
		}
	}
}

int check_username(char un[], int sockfd)
{
	SLIST_FOREACH(np, &head, list)
	{
		if(strncmp(np->Username, un, MAX) == 0)//does username already exist in linked list
		{
			return 0;
		}
	}
	struct client *new_client = malloc(sizeof(struct client));//create space for
	strncpy(new_client->Username, un, MAX);//add their username
	new_client->Username[MAX-1] = '\0';//ensure null terminator
	new_client->sockfd = sockfd;//copy socket
	SLIST_INSERT_HEAD(&head, new_client, list);//add to list
	return 1;
}

void remove_client(int sockfd)
{
    SLIST_FOREACH(np, &head, list) {
        if (np->sockfd == sockfd) {
            SLIST_REMOVE(&head, np, client, list);//remove client from linked list
            free(np);//free client linked list memory
            break;
        }
    }
}

void encode(char *str, char c)
{
	memmove(str + 1, str, strnlen(str, MAX) + 1);//move string over
	str[0] = c;//insert character
}
