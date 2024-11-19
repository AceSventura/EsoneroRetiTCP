/*
 * 19/11/2024
 *
 * authors: Fabio Gargaro, Alexandro Gabriele Capuano
 */

#if defined WIN32
	#include <winsock.h>
#else
	#include <string.h>
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#define closesocket close
#endif

#include <stdio.h>
#include "protocol.h"

void clearwinsock() {
#if defined WIN32
	WSACleanup();
#endif
}

void errorhandler(char *errorMessage) {
	printf("%s", errorMessage);
}


// Function to parse the input string and store the values in the pwd_message struct
int parse_input(const char* input, pwd_message* pwd_msg) {
    // Check if the input or pwd_msg are NULL
    if (input == NULL || pwd_msg == NULL) {
        printf("Invalid arguments.\n");
        return -1; // Error: invalid arguments
    }


    // Use sscanf to read the input string
    int num_items = sscanf(input, "%c %d", &(pwd_msg->type_pwd), &(pwd_msg->length_pwd));

    // Check if sscanf successfully read the expected number of items
    if (num_items != 2) {
        printf("Invalid input format. Expected format: \"%%c %%d\".\n");
        return -1; // Error: input format is not correct
    }

    // Check if the password length is valid
    if (pwd_msg->length_pwd < 6 || pwd_msg->length_pwd > 32) {
        printf("Password length must be in [6-32].\n");
        return -1; // Error: invalid password length
    }
    // Check if the chars are in [n, a, m, s]
	switch(pwd_msg->type_pwd){
		case 'n':
		case 'a':
		case 'm':
		case 's':
			return 0;
		default:
			printf("Type must be any of [n, a, m, s].\n");
			return -1;
	}

    return 0; // Success
}

int main(int argc, char *argv[]) {
#if defined WIN32
	// Initialize Winsock
	WSADATA wsa_data;
	int result = WSAStartup(MAKEWORD(2,2), &wsa_data);
	if (result != NO_ERROR) {
		printf("Error at WSAStartup()\n");
		return 0;
	}
#endif

	while (1) {
		// create client socket
		int c_socket;
		c_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (c_socket < 0) {
			errorhandler("socket creation failed.\n");
			closesocket(c_socket);
			clearwinsock();
			return -1;
		}

		// set connection settings
		struct sockaddr_in sad;
		memset(&sad, 0, sizeof(sad));
		sad.sin_family = AF_INET;
		char* serverIP = "127.0.0.1";
		sad.sin_addr.s_addr = inet_addr(serverIP); // Server IP
		sad.sin_port = htons(PROTO_PORT); // Server port

		// connection
		if (connect(c_socket, (struct sockaddr*) &sad, sizeof(sad)) < 0) {
			errorhandler("Failed to connect.\n");
			closesocket(c_socket);
			clearwinsock();
			return -1;
		}

		// receive from server
		char buffer[BUFFER_SIZE];
		memset(buffer, '\0', BUFFER_SIZE);
		if ((recv(c_socket, buffer, BUFFER_SIZE - 1, 0)) <= 0) {
			errorhandler("recv() failed or connection closed prematurely");
			closesocket(c_socket);
			clearwinsock();
			return -1;
		}
		printf("%s\n", buffer); // Print the echo buffer

		// User Menu
		printf("n: numeric password (digits only)\n");
		printf("a: alphabetic password (lowercase letters only)\n");
		printf("m: mixed password (lowercase letters and digits)\n");
		printf("s: secure password (uppercase letters, lowercase letters, digits, and symbols)\n");
		printf("Enter the type of password to generate with its length [es. n 8] (or type 'q' to quit): ");

		// Read input from user (password's type and length)
		char input[100];
		pwd_message pwd_msg;
		fgets(input, sizeof(input), stdin);

		// Check for exit condition
		if (strncmp(input, "q", 1) == 0) {
			printf("Connection closed.\n");

			pwd_msg.length_pwd = -1;
			send(c_socket, &pwd_msg, sizeof(pwd_message), 0);

			closesocket(c_socket);
			clearwinsock();
			break; // Exit the loop
		}


		// Call the function to parse the input
		while (parse_input(input, &pwd_msg) != 0) {
			printf("Incorrect format inserted.\n");
			printf("Enter the type of password to generate with its length [es. n 8] (or type 'q' to quit): ");
			fgets(input, sizeof(input), stdin);

			// Check for exit condition
			if (strncmp(input, "q", 1) == 0) {
				printf("Connection closed.\n");

				pwd_msg.length_pwd = -1;
				send(c_socket, &pwd_msg, sizeof(pwd_message), 0);

				closesocket(c_socket);
				clearwinsock();
				break; // Exit the loop
			}
		}

		// send data to server
		if (send(c_socket, &pwd_msg, sizeof(pwd_message), 0) != sizeof(pwd_message)) {
			errorhandler("send() sent a different number of bytes than expected");
			closesocket(c_socket);
			clearwinsock();
			return -1;
		}

		char password[pwd_msg.length_pwd+1];
		memset(password, '\0', sizeof(password));
		// get reply from server
		if ((recv(c_socket, password, (sizeof(char)*pwd_msg.length_pwd+1), 0)) <= 0) {
			errorhandler("recv() failed or connection closed prematurely");
			closesocket(c_socket);
			clearwinsock();
			return -1;
		}

		// Write the generated password on stdout
		printf("Password generated: %s\n", password);
		printf("**********************************\n");
		closesocket(c_socket);
		clearwinsock();
	}

	return 0;

} // main end
