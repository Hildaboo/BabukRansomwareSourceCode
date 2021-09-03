#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include "curve25519-donna.h"
#include "sosemanuk.h"
#include "sha256.h"

static uint8_t basepoint[32] = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static uint8_t m_priv[32] = {
        'c', 'u', 'r', 'v', 'p', 'a', 't', 't', 'e', 'r', 'n', 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define CONST_1MB 1048576ll
#define CONST_BLOCK (CONST_1MB * 10)

void decrypt_file(char* path) {
	unsigned long wholeReaded = 0;
	size_t readed = 0;
	
	uint8_t u_publ[32];
	uint8_t u_secr[32];
	uint8_t sm_key[32];
	struct stat64 fstat;
	
	sha256_context sc;
	sosemanuk_key_context kc;
	sosemanuk_run_context rc;
	
	if(stat64(path, &fstat) == 0){
		if(fstat.st_size > 32) {
			if (FILE *fp_key = fopen(path, "r+b")) {
				if(fseek(fp_key, -32, SEEK_END) == 0) {
					fread(u_publ, 1, 32, fp_key);
					curve25519_donna(u_secr, m_priv, u_publ);
					
					sha256_init(&sc);
					sha256_hash(&sc, u_secr, 32);
					sha256_done(&sc, sm_key);
					
					sosemanuk_schedule(&kc, sm_key, 32);
					sosemanuk_init(&rc, &kc, 0, 0);
				}
				fclose(fp_key);
				truncate64(path, fstat.st_size - 32);
				
				if (FILE *fp = fopen(path, "r+b")) {
					if(uint8_t* f_data = (uint8_t*)malloc(CONST_BLOCK)) {
						do {
							wholeReaded += readed = fread(f_data, 1, CONST_BLOCK, fp);
							if(readed) {
								sosemanuk_encrypt(&rc, f_data, f_data, readed);
								fseek(fp, -readed, SEEK_CUR);
								fwrite(f_data, 1, readed, fp);
							} else break;
						} while(wholeReaded < 0x20000000 && wholeReaded < (fstat.st_size - 32));
						
						free(f_data);
					}
					fclose(fp);
					
					char unlocked_name[4096];
					strcpy(unlocked_name, path);
					for (int i = strlen(unlocked_name); i >= 0; i--) {
						if (unlocked_name[i] == '.') {
							unlocked_name[i] = 0;
							break;
						}
					}
					rename(path, unlocked_name);
				}
			}
		}
	}
}

void find_files_recursive(char* begin) {
	if(char* path = (char*)malloc(4096)) {
		strcpy(path, begin);
		if (DIR* entry = opendir(path)) {
			dirent* record = 0;
			while ((record = readdir(entry)) != NULL) {
				if(strcmp(record->d_name, "..") != 0 && strcmp(record->d_name, ".") != 0) {
					if(record->d_type == DT_DIR) {
						strcpy(path, begin);
						strcat(path, "/");
						strcat(path, record->d_name);
						find_files_recursive(path);
					} else if(record->d_type == DT_REG) {
						if(strstr(record->d_name, ".babyk") != 0) {
							strcpy(path, begin);
							strcat(path, "/");
							strcat(path, record->d_name);
							
							printf("Decrypting: %s\n", path);
							decrypt_file(path);
						}
					}
				}
			}
			closedir(entry);
		}
		
		strcpy(path, begin);
		strcat(path, "/How To Restore Your Files.txt");
		unlink(path);
		
		free(path);
	}
}

int main(int argc, char* argv[]) {
	if(argc == 2) {
		find_files_recursive(argv[1]);
	} else {
		printf("Usage: %s /begin/path\n", argv[0]);
	}
	return(0);
}