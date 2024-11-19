/*
 * 19/11/2024
 *
 * authors: Fabio Gargaro, Alexandro Gabriele Capuano
 */
#if defined WIN32
#include <winsock.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#define closesocket close
#endif

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "protocol.h"

void clearwinsock() {
#if defined WIN32
	WSACleanup();
#endif
}

void errorhandler(char *errorMessage) {
	printf("%s", errorMessage);
}

// Function to generate a full numeric password
void generate_numeric(char* psw, int length) {
    for (int i = 0; i < length; i++) {
        int r = rand() % 10;
        psw[i] = '0' + r;
    }
    psw[length] = '\0';

}

// Function to generate a lowercase alpabetic password
void generate_alpha(char* psw, int length) {

    for (int i = 0; i < length; i++) {
        char r = 'a' + rand() % 26;
        psw[i] = r;
    }
    psw[length] = '\0';

}

// Function to generate a mixed (lowercases, uppercases, numerical) password
void generate_mixed(char* psw, int length) {

    psw[0] = 'A' +rand()%26;
	psw[1] = 'a' +rand()%26;
	psw[2] = rand()%10;

    for (int i = 3; i < length; i++) {
        char r = (rand() % 2) ? ('a' + rand() % 26) : ('A' + rand() % 26);
        psw[i] = r;
    }
    psw[length] = '\0';
}

// Function to generate a secure password (mixed password with special chars)
void generate_secure(char* psw, int length) {
	char special[] = "!@#$%^&*()_-+=<>?";

    // Being sure having all of the requirements types of chars
    psw[0] = 'A' + rand()%26;
    psw[1] = 'a' + rand()%26;
    psw[2] = '0' + rand()%10;
    psw[3] = special[rand() % strlen(special)];

    for (int i = 4; i < length; i++) {
    	int opt = rand()%4;
    	switch(opt){
			case 0:
				psw[i] = 'A' +rand()%26;
				break;
    		case 1:
    			psw[i] = 'a' +rand()%26;
    			break;
    		case 2:
    			psw[i] = '0' + rand()%10;
    			break;
    		case 3:
    			psw[i] = special[rand() % strlen(special)];
    			break;
    	}
    }

    psw[length] = '\0';
}

// MAIN
int main(int argc, char *argv[]) {
#if defined WIN32
	WSADATA wsa_data;
	int result = WSAStartup(MAKlEWORD(2,2), &wsa_data);
	if (result != NO_ERROR) {
		printf("Error at WSAStartup()\n");
		return 0;
	}
#endif

	srand(time(NULL));	// initialization of random

	// Socket configurations
	int my_socket;
	my_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (my_socket < 0) {
		errorhandler("socket creation failed.\n");
		clearwinsock();
		return -1;
	}

	struct sockaddr_in sad;
	memset(&sad, 0, sizeof(sad));
	sad.sin_family = AF_INET;
	char* clientIP = "127.0.0.1";
	sad.sin_addr.s_addr = inet_addr(clientIP);
	sad.sin_port = htons(PROTO_PORT);

	if (bind(my_socket, (struct sockaddr*) &sad, sizeof(sad)) < 0) {
		errorhandler("bind() failed.\n");
		closesocket(my_socket);
		clearwinsock();
		return -1;
	}

	// Server listening
	if (listen(my_socket, QLEN) < 0) {
		errorhandler("listen() failed.\n");
		closesocket(my_socket);
		clearwinsock();
		return -1;
	}

	struct sockaddr_in cad;
	int client_socket;
	int client_len;
	printf("Waiting for a client to connect...\n\n");
	while (1) {
		client_len = sizeof(cad);
		if ((client_socket = accept(my_socket, (struct sockaddr*) &cad, &client_len)) < 0) {
			errorhandler("accept() failed.\n");
			closesocket(client_socket);
			clearwinsock();
			return 0;
		}

		printf("New connection from %s:%d\n", clientIP, PROTO_PORT);

		char *s = "Connection established";
		if (send(client_socket, s, strlen(s), 0) != strlen(s)) {
			errorhandler("send() sent a different number of bytes than expected");
			closesocket(client_socket);
			clearwinsock();
			return -1;
		}

		// Message receiving
		pwd_message msg;
		if ((recv(client_socket, &msg, sizeof(msg), 0)) <= 0) {
			errorhandler("recv() failed or connection closed prematurely");
			closesocket(client_socket);
			clearwinsock();
			return -1;
		}else if(msg.length_pwd != -1){
			// Generation of password dipending by its length and type
			char* password = (char*)malloc((msg.length_pwd + 1) * sizeof(char));
			memset(password, '\0', sizeof(password));

			switch(msg.type_pwd) {
				case 'n':
					generate_numeric(password, msg.length_pwd);
					break;
				case 'a':
					generate_alpha(password, msg.length_pwd);
					break;
				case 'm':
					generate_mixed(password, msg.length_pwd);
					break;
				case 's':
					generate_secure(password, msg.length_pwd);
					break;
			}

			// Sending generated password
			if (send(client_socket, password, (sizeof(char)*msg.length_pwd+1), 0) != (sizeof(char)*msg.length_pwd+1)) {
				errorhandler("send() sent a different number of bytes than expected");
				closesocket(client_socket);
				clearwinsock();
				return -1;
			}
		}

	}
}
