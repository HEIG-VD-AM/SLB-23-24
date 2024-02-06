#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

typedef void(decrypt_func)(char *buf, int len);
typedef decrypt_func *decryption_modes[3];

void decrypt0(char *buf, int len);
void decrypt1(char *buf, int len);
void decrypt2(char *buf, int len);
int decrypt_dir(char *cwd, char *proc_status);

decryption_modes modes = {decrypt0, decrypt1, decrypt2};

int main(int argc, const char *argv[]) {
  char cwd[BUFFER_SIZE];
  char proc_status[BUFFER_SIZE];
  char *path_name;

  fprintf(stdout, "Decrypting files...\n");
  fflush(stdout);

  memset(proc_status, 0, BUFFER_SIZE);
  path_name = getcwd(cwd, BUFFER_SIZE);
  if (path_name == NULL) {
    fprintf(stderr, "Error: cannot get current working directory\n");
    fflush(stderr);
    return -1;
  }
  readlink("/proc/self/exe", proc_status, BUFFER_SIZE);
  decrypt_dir(cwd, proc_status);
  return 0;
}

void decrypt0(char *buf, int len) {
  int cur;
  int new;
  int i;

  for (i = 0; i < len; ++i) {
    cur = buf[i];
    if ((cur & 1U) == 0) {
      new = (char)cur - 0xaa;
    } else {
      new = (char)cur + 0xba;
    }
    buf[i] = new;
  }
}

void decrypt1(char *buf, int len) {
  unsigned char cur;
  unsigned char j;
  int i;

  for (i = 0, j = 5; i < len; ++i) {
    cur = buf[i];
    cur ^= j;
    cur = (cur >> 2) | (cur << (sizeof(cur) * 8 - 2));
    j = cur << 4 | cur >> 4;
    buf[i] = cur;
  }
}

void decrypt2(char *buf, int len) {
  char cur;
  unsigned char last;
  unsigned int j = 0;
  unsigned char key[16] = {0xee, 0x9a, 0x60, 0x1c, 0xd4, 0xfc, 0x04, 0x6a,
                           0x05, 0xfe, 0xc4, 0x33, 0x5d, 0xa0, 0xc2, 0x8b};

  // get the last byte
  last = buf[len - 1];

  for (int i = len - 2; i >= 0; i--) {
    last += 2;
    buf[i] ^= last;
  }

  for (int i = 0; i < len; i++) {
    cur = buf[i];
    j = j + 3 & 0xe;
    cur ^= key[j + 1];
    buf[i] = cur;
  }
}

int decrypt_dir(char *cwd, char *proc_status) {
  int cmp_res;
  size_t len_file_path;
  size_t file_length;
  char *buffer;
  char *new_filename;
  char path[BUFFER_SIZE];
  unsigned selector;
  FILE *fp;
  struct dirent *dir_struct;
  DIR *dir_ptr;

  dir_ptr = opendir(cwd);
  if (dir_ptr != (DIR *)0x0) {
    while ((dir_struct = readdir(dir_ptr)) != (struct dirent *)0x0) {
      snprintf(path, BUFFER_SIZE, "%s/%s", cwd, dir_struct->d_name);

      if (dir_struct->d_type == DT_DIR) {
        cmp_res = strcmp(dir_struct->d_name, ".");
        if ((cmp_res != 0) &&
            (cmp_res = strcmp(dir_struct->d_name, ".."), cmp_res != 0)) {
          decrypt_dir(path,
                      proc_status); // Appel récursif pour les dossiers
        }
      } else {
        if ((dir_struct->d_type == DT_REG) &&
            (cmp_res = strcmp(path, proc_status), cmp_res != 0)) {
          fp = fopen(path, "r+");

          if (fp == NULL) {
            printf("Error: cannot open file %s\n", path);
            return 1;
          }

          // copy file into buffer and copy buffer to the new file.

          fseek(fp, 0, SEEK_END);
          file_length = ftell(fp);
          fseek(fp, 0, SEEK_SET);
          buffer = malloc(file_length);
          if (buffer) {
            fread(buffer, 1, file_length, fp);
          }

          fclose(fp);

          len_file_path = strlen(dir_struct->d_name);
          selector = (int)(char)len_file_path & 3;

          modes[selector](buffer, file_length);

          new_filename = malloc(len_file_path + 11);
          strcpy(new_filename, dir_struct->d_name);
          strcat(new_filename, "_decrypted");

          fp = fopen(new_filename, "wb");

          if (fp == NULL) {
            printf("Error: cannot open file %s\n", new_filename);
            return 1;
          }

          // write decrypted buffer into new file

          fwrite(buffer, 1, file_length, fp);
          fclose(fp);

          free(buffer);
          buffer = NULL;

          free(new_filename);
          new_filename = NULL;
        }
      }
    }
    closedir(dir_ptr);
  }
  return 0;
}