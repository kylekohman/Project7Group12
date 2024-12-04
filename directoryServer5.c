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
	char serverName[MAX], to[MAX], fr[MAX];;
	int port;
	int sockfd;
	char *tooptr, *froptr;
	SLIST_ENTRY(server)
	list;
} *np;

int check_server_uniqueness(char *, int, struct server*);
char *display_servers();
void encode(char *, char);
int find_server_port(char *);
int set_nonblocking(int sock);
struct server* remove_server(struct server* ser);

int main(int argc, char **argv)
{
	int sockfd, newsockfd, maxfd, port, n;
	unsigned int clilen;
	struct sockaddr_in cli_addr, serv_addr;
	char s[MAX];
	fd_set readset, writeset;

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

	for (;;)
	{

		FD_ZERO(&readset);//clear read set
		FD_SET(sockfd, &readset);//add the server
		FD_ZERO(&writeset);//clear the write set
		maxfd = sockfd;// init maxfd
		
		struct server* p;
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

		memset(s, 0, MAX); // reset message

		if (select(maxfd + 1, &readset, &writeset, NULL, NULL) < 0)
		{ // select
			perror("dir_server: select error");
			exit(1);
		}

		if (FD_ISSET(sockfd, &readset))//new server/client connection 
		{ // new connection
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0)
			{
				perror("server: accept error");
				exit(1);
			}

			//set server to nonblocking
			if(set_nonblocking(newsockfd) < 0){
				close(newsockfd);
				continue;
			}

			struct server *new_s = (struct server *)malloc(sizeof(struct server));
			if(!new_s){//check malloc success
				perror("dir_server: failed to malloc new server");
				close(newsockfd); //close if failure
				continue;
			} 
			new_s->sockfd = newsockfd; //set the new socket

			//ensure username and buffers are set clean
		    memset(new_s->serverName, 0, MAX);
			//snprintf(new_s->serverName, MAX, "\0");//init the username to null term POSSIBLY REMVOE
			memset(new_s->to, 0, MAX);
            memset(new_s->fr, 0, MAX);

			// Initialize buffer pointers 
			new_s->tooptr = new_s->to; 
			new_s->froptr = new_s->fr; 
			//port = ntohs(cli_addr.sin_port);
			//fprintf(stderr, "%s:%d Accepted client connection from %s %d\n", __FILE__, __LINE__, inet_ntoa(cli_addr.sin_addr), port); // debug
			/*FD_SET(newsockfd, &readset); // add new socket to read set
			// update maxfd if necessary
			if (newsockfd > maxfd)
			{
				maxfd = newsockfd;
			}*/
			SLIST_INSERT_HEAD(&head, new_s, list);
		}

		struct server* np = SLIST_FIRST(&head);
		while(np != NULL)
		{
			char temp[MAX];
			if (FD_ISSET(np->sockfd, &readset))
			{
				if ((n = read(np->sockfd, np->froptr, &(np->fr[MAX]) - np->froptr)) < 0)
				{		
					if (errno != EWOULDBLOCK) { 
						perror("read error on socket");
						np = remove_server(np);
					}				 // close the connection to client
				}
				else if(n == 0)//server disconnects
				{
					np = remove_server(np);//remove client from the linked list
					continue;
				}
				else
				{ // Client message
					fprintf(stderr, "DIR SERVER RECEIVED: %s\n", np->fr);//debug
					np->froptr += n;

					if (np->froptr > &(np->fr[MAX])) { // If the progress pointer reaches the end of the buffer, reset it 
						fprintf(stderr, "Inside the if\n");
						np->froptr = np->fr[MAX - 1];
						np->fr[MAX - 1] = '\0';
					}

					char code = np->fr[0];//remove first character
					memmove(np->fr, np->fr + 1, np->froptr - (np->fr + 1));//remove the encoding from the message
					np->froptr--;//need to check memory here

					switch (code)
					{
						case 'x': // server attempting to connect
							parse_message(np->fr, temp, &port);
							if (!check_server_uniqueness(temp, port, np)) // see if server exists in the linked list already
							{		
								add_to_writebuff("dServer name or port already in use", np);										  
								close(np->sockfd);	//this needs to be removed I think
								//FD_CLR(i, &readset);								  // remove from readset
							}
							else
							{
								snprintf(np->serverName, MAX, "%s", temp);
								np->serverName[MAX - 1] = '\0';					   // ensure null terminator
								np->port = port;
							}
							break;
						case 'n':							// new client request to see the server option
						//consider allocating memory for list here
							char *menu = display_servers(); // display server options
							add_to_writebuff(menu, np);
							free(menu);						// free memory
							break;
						case 'c': // the clients 'c'hoice of server
							port = find_server_port(np->fr);
							memset(s, 0, MAX); // reset message
							if (port == -1)
							{ // port not found
								add_to_writebuff("oPlease Enter a Valid Chat Server Name\n", np);
							}
							else
							{
								snprintf(s, MAX, "%d", port); // successfully found port
								encode(s, 'b');
								add_to_writebuff(s, np);
								
								//FD_CLR(i, &readset);		   // remove the client from the directory server's readset
							}
							break;
						default:
							fprintf(stderr, "Invalid request\n");
					}
				}
			}//end readset check
			
			//Writeset check
			if(FD_ISSET(np->sockfd, &writeset) && (n = (&(np->to[MAX]) - np->tooptr)) > 0){
				ssize_t nwrite = write(np->sockfd, np->to, MAX);//n);
				if (nwrite < 0 && errno != EWOULDBLOCK) { 
					perror("write error on socket");
					np = remove_server(np);
					continue;
				}
				else { 
					np->tooptr += nwrite;//XXXX
					if (&(np->to[MAX]) == np->tooptr) { // All data sent 
						np->tooptr = np->to; 
					}
				}
			}//end of writeset check
		//struct server* np2 = SLIST_NEXT(np, list);
		np = SLIST_NEXT(np, list);
		}//end of while loop
	}//end of main loop
}//end of main

int check_server_uniqueness(char *t, int p, struct server* ser)
{
	struct server* s;
	SLIST_FOREACH(s, &head, list)
	{
		if ((strncmp(s->serverName, t, MAX) == 0) || s->port == p) // does username or port already exist in linked list
		{
			return 0;
		}
	}

	return 1;												   // success
}

char *display_servers() // method for displaying active chat servers
{
	char* format_line = "=================================\n";
	char *display_string = malloc(MAX * 5);
	if(display_string == NULL)
	{
		perror("Unable to allocate memory for display_string");
		return NULL;
	}
	char buffer[MAX];
	int count = 1;
	int offset = snprintf(display_string, MAX * 5, "%sSERVER LIST: Number: Name - Port\nEnter Server Name to Join\n%s", format_line, format_line);
	//snprintf(display_string, MAX, "%sSERVER LIST: Number: Name - Port\nEnter Server Name to Join\n%s", format_line, format_line);
	if (SLIST_EMPTY(&head))
	{
		snprintf(display_string + offset, MAX * 5 - offset, "%s", "No Chat Servers Currently Online\n");
	}
	else
	{
		struct server* i;
		SLIST_FOREACH(i, &head, list)
		{
			if(strncmp(i->serverName, "\0", MAX) != 0 )
			{
				int written = snprintf(buffer, MAX, "%d: %s - %d\n", count, i->serverName, i->port);
				int added = snprintf(display_string + offset, MAX * 5 - offset, "%s", buffer);
				//strncat(display_string, buffer, MAX);
				offset += added;
				count++;
			}
		}
	}
	//char temp[MAX];
	//snprintf(temp, MAX, display_string);
	snprintf(display_string + offset, MAX * 5 - offset, "%s", format_line);
	return display_string;
}

void parse_message(char *input, char *serverName, int *port)
{
	/*
	if (2 == sscanf(input, "%s%[^~]~%d", serverName, port)){
		return 0;
	}
	return 1;
	*/
	
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
		strncpy(serverName, input, delimiter); //change this to snprintf
		serverName[delimiter] = '\0'; // ensure null terminator
		int i = sscanf(input + delimiter + 1, "%d", port); //this too probably
		/*if (1 != i) return 1;
		else return 0;*/
	}/*
	else {
		return 1;
	}*/
}

void encode(char *str, char c)
{
	char temp[MAX];
	snprintf(temp, MAX, "%c%s", c, str);
	snprintf(str, MAX, temp);								  // insert character
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

/// @brief removes a server from the linked list
/// @param ser the server to remove
struct server* remove_server(struct server* ser)
{
	close(ser->sockfd);
	struct server* n2 = SLIST_NEXT(ser, list);
	SLIST_REMOVE(&head, ser, server, list);//remove server from linked list CHECK
	free(ser);
	return n2;
}

/// @brief Adds a message to a specific servers writebuff
/// @param message the message to add to the buffs
/// @param s the source server
void add_to_writebuff(char* message, struct server* s){
	int len = strnlen(message, MAX) + 1;//maybe remove
	snprintf(s->tooptr, &(s->to[MAX]) - s->tooptr, "%s", message);//add to buffer
	s->tooptr += len;//update the pointer
	//check if there is room in the buffer
	/*
	if((s->tooptr + len) < &(s->to[MAX])){
		snprintf(s->tooptr, &(s->to[MAX]) - s->tooptr, "%s", message);//add to buffer
		s->tooptr += len;//update the pointer
	}
	*/
}
