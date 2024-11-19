#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define PROTO_PORT 20000
#define BUFFER_SIZE 32

typedef struct {
	char type_pwd;
	int length_pwd;
} pwd_message;

#endif
