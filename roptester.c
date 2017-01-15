#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>

#define MAX_INPUT_LEN	1024
#define MAX_CMD_LEN	MAX_INPUT_LEN + 32

int main(int argc, char *argv[])
{
	char buf[256];
	FILE *file;
	char *cmd;
	int i;
	int len = 0;
	void *dll = NULL;
 
	if (argc < 2) {
		printf("Invalid arguments.\n");
		printf("Usage: %s <libfile1> <libfile2> <libfile3> ...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	cmd = calloc(MAX_CMD_LEN, sizeof(char));
	if (!cmd) {
		printf("[-] Failed to allocate memory\n");
		exit(EXIT_FAILURE);
	}

	sprintf(cmd, "python rebase_offsets.py %d exploit.py", getpid());
	for (i = 1; i < argc; i++) {
		dll = dlopen(argv[i], RTLD_NOW);
		if (!dll) {
			printf("[-] Failed to load library: %s\n", argv[i]);
			exit(EXIT_FAILURE);
		} else {
			printf("[*] Loaded library: %s\n", argv[i]);
		}
		len += strlen(argv[i]);
		if (len >= MAX_INPUT_LEN) {
			printf("\n** Exceeds max input length **\n");
			exit(EXIT_FAILURE);
		}
		cmd[strlen(cmd)] = ' ';
		strcat(cmd, argv[i]);
	}

	printf("[*] Rebasing offsets in exploit.py\n");
	system(cmd);
	free(cmd);
	
	printf("[*] Launching paylod\n[*]\n");
	
	file = fopen("payload.out", "rb");
	if (!file) {
		printf("[-] Failed to open payload.out file\n");
		exit(EXIT_FAILURE);
	}

	i = fseek(file, 0, SEEK_END);
	if (i < 0) {
		printf("[-] Failed to fseek on payload.out\n");
		exit(EXIT_FAILURE);
	}
	
	len = ftell(file);
	if (i < 0) {
		printf("[-] Failed to ftell payload.out\n");
		exit(EXIT_FAILURE);
	}

	i = fseek(file, 0, SEEK_SET);
	if (i < 0) {
		printf("[-] Failed to fseek on payload.out\n");
		exit(EXIT_FAILURE);
	}

	fread(buf, 1, len, file);
}
