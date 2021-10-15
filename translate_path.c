#define _GNU_SOURCE // <-- This is needed for RTLD_NEXT btw.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <regex.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#define FILE_NAME "/var/myfile"


typedef FILE* (*orig_fopen_func_type)(const char *path, const char *mode);
typedef int (*orig_open_func_type)(const char *pathname, int flags);
typedef int (*orig_mkdir_func_type)(const char *pathname, mode_t mode);
typedef int (*orig_open_var_func_type)(const char *pathname, int flags, int mode);

int (*old_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = NULL;

static int (*old_xstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static int (*old_lxstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_lxstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static int (*old_getxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
static int (*old_lgetxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
static int (*old_listxattr)(const char *path, char *list, size_t size) = NULL;
static int (*old_llistxattr)(const char *path, char *list, size_t size) = NULL;
//static int (*old_readlink)(const char *pathname, char *buf, size_t bufsiz) = NULL;
static int (*old_access)(const char *pathname, int mode) = NULL;
static int (*old_rename)(const char *pathname, const char *newpath) = NULL;
static int (*old_unlink)(const char *path) = NULL;

static int (*real_stat)(const char *str, struct stat *buf);
static int (*real_lstat)(const char *str, struct stat *buf);


char system_path[][25] = { "/proc", "/dev", "/usr", "/var", "/srv" , "/sbin",
                           "/opt", "/run", "/root", "/selinux", "/bin", "/data",
                           "/lib", "/etc", "/sys", "/tmp", "/home/gmadmin", "/home/gridmarkets",
                           "/local", "/modules", "/2020"};


int compile_regex(regex_t *regex, const char *pattern)
{
    int value;
    value = regcomp(regex, pattern, 0);
    return value;
}


bool startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : memcmp(pre, str, lenpre) == 0;
}


/*
char *recover_filename(FILE *f)
{
    char fd_path[256];
    int fd = fileno(f);
    sprintf(fd_path, "/proc/self/fd/%d", fd);
    char *filename = malloc(256);
    int n;
    if ((n = readlink(fd_path, filename, 255)) < 0)
        return NULL;
    filename[n] = '\0';
    return filename;
}
*/


int skip_normalise(const char *path){
  for( int i = 0; i < sizeof(system_path)/sizeof(system_path[0]); i++){
    if( startsWith(system_path[i], path) ){
      return 0;
    }
  }
  return 1;
}


void normalise_path(const char *project, const char *path, char *norm_path){
  // Var declaration
  regex_t slash_regex,
          colon_regex,
          drive_char_regex,
          drive_char_no_slash_regex;
  char drive_char;
  int path_len;

  //printf("Path [%s]\n", path);
  // Initialise
  memset(norm_path, '\0', sizeof(norm_path));
  compile_regex(&slash_regex, "^/.[A-Z,a-z,0-9]");
  compile_regex(&colon_regex, "^[A-Z,a-z]:");
  compile_regex(&drive_char_regex, "^/[A-Z,a-z]/");
  compile_regex(&drive_char_no_slash_regex, "^[A-Z,a-z]/");

  if ((strchr(path, ':') != NULL ) && (startsWith(project, path))) {
    //printf("Colon in path starts with project directory\n");
    //split project path and normalise
    path_len = strlen(path) - 1;
    while (path_len >= 0) {
      drive_char = path[1];
      if (drive_char == ':') {
        break;
      }
      path++;
      path_len--;
    }
    //printf("Local absolute path mixed up [%s]\n", path);
    normalise_path(project, path, norm_path);
    for (int i=0; i < strlen(norm_path)-1; i++) {
      if ((norm_path[i] == 92) && (norm_path[i+1] != ' ')) {
        norm_path[i] = '/';
      }
    }
    //printf("Remaped path [%s]\n", norm_path);
  }
  // pattern match and normalise
  else if ((skip_normalise(path)) != 0){
    if (regexec(&slash_regex, path, 0, NULL, 0) == 0){
      strcat(norm_path, project);
      // forward slash as in linux root path
      path++;
      //strcat(norm_path, project);
      strcat(norm_path, path);
    } else if (regexec(&drive_char_regex, path, 0, NULL, 0) == 0){
      norm_path[0] = toupper(path[1]);
      // forward slash as in linux root path
      path++;
      //strncat(norm_path, path, 1);
      // drive char
      path++;
      strcat(norm_path, "__gm_colon__");
      strcat(norm_path, path);
    } else if (regexec(&drive_char_no_slash_regex, path, 0, NULL, 0) == 0){
      norm_path[0] = toupper(path[0]);
      // forward slash as in linux root path
      //path++;
      //strncat(norm_path, path, 1);
      // drive char
      path++;
      strcat(norm_path, "__gm_colon__");
      strcat(norm_path, path);
    } else if (regexec(&colon_regex, path, 0, NULL, 0) == 0){
      strcat(norm_path, project);
      // Windows drive match
      // drive_char = tolower(*path);
      strncat(norm_path, path, 1);
      path++;
      strcat(norm_path, "__gm_colon__");
      path++;
      strcat(norm_path, path);
    } else {
      strcat(norm_path, path);
    }
  } else {
    strcat(norm_path, path);
  }
 //printf("Norm Path [%s]\n", norm_path);
}

int passthrough(const char *norm_path, int flags, va_list args){
  // If O_CREAT is used, pass on the third parameter "mode":
  if (flags & O_CREAT) {
    //printf("CREATE...\n");
    orig_open_var_func_type orig_func;
    orig_func = (orig_open_var_func_type)dlsym(RTLD_NEXT, "open");
    int mode = va_arg(args, int);
    va_end(args);
    //printf("before creatig file: [%s] [%d]\n", norm_path, flags);
    return orig_func(norm_path, flags, 0644);

  } else {
    //printf("Path: [%s], Flags [%d]\n", norm_path, flags);
    orig_open_func_type orig_func;
    orig_func = (orig_open_func_type)dlsym(RTLD_NEXT, "open");
    return orig_func(norm_path, flags);
  }
}


int mkdir(const char *pathname, mode_t mode)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(pathname) + 13];
  normalise_path(project, pathname, norm_path);
  //printf("Normalised mdir path [%s]\n", norm_path);
  orig_mkdir_func_type orig_func;
  orig_func = (orig_mkdir_func_type)dlsym(RTLD_NEXT, "mkdir");
  return orig_func(norm_path, mode);
}

int open(const char *pathname, int flags, ...)
{
  //log_file_access(pathname);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(pathname) + 13];
  normalise_path(project, pathname, norm_path);
  //printf("Normalised open path [%s]\n", norm_path);
  va_list args;
  va_start(args, flags);
  return passthrough(norm_path, flags, args);
}


FILE* fopen(const char *pathname, const char *mode)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(pathname) + 13];
  normalise_path(project, pathname, norm_path);
  //printf("Normalised fopen path [%s]\n", norm_path);
  orig_fopen_func_type orig_func;
  orig_func = (orig_fopen_func_type)dlsym(RTLD_NEXT, "fopen");
  return orig_func(norm_path, mode);
}

FILE* fopen64(const char *pathname, const char *mode)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(pathname) + 13];
  normalise_path(project, pathname, norm_path);
  //printf("Normalised fopen64 path [%s]\n", norm_path);
  orig_fopen_func_type orig_func;
  orig_func = (orig_fopen_func_type)dlsym(RTLD_NEXT, "fopen64");
  return orig_func(norm_path, mode);
}

int open64(const char *pathname, int flags, ...)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(pathname) + 13];
  normalise_path(project, pathname, norm_path);
  //printf("Normalised open64 path [%s]\n", norm_path);
  va_list args;
  va_start(args, flags);
  return passthrough(norm_path, flags, args);
}


/*
typedef ssize_t (*execve_func_t)(const char* filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;
int execve(const char* filename, char* const argv[], char* const envp[]) {
    //printf("Running hook\n");
    old_execve = dlsym(RTLD_NEXT, "execve");
    return old_execve(filename, argv, envp);
}
*/


DIR *opendir(const char *name) {
  //printf("opendir [%s]\n", name);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(name) + 13];
  normalise_path(project, name, norm_path);
  //printf("opendir [%s], normalised [%s]\n", name, norm_path);
  name = norm_path;
  DIR *(*libc_opendir)(const char *name);
  *(void **)(&libc_opendir) = dlsym(RTLD_NEXT, "opendir");
  //printf("opendir [%s]\n", name);
  return libc_opendir(norm_path);
  DIR *(*orig_opendir)(const char*) = dlsym(RTLD_NEXT, "opendir");
  DIR *dir = orig_opendir(name);
  return dir;
}


struct dirent *readdir(DIR *dir) {
  //printf("readdir [%s]\n", dir->d_name);
  //printf("readdir\n");
  struct dirent *(*orig_readdir)(DIR*) = dlsym(RTLD_NEXT, "readdir");
  struct dirent *entry;
  entry = orig_readdir(dir);
  return entry;
}

int getxattr(const char *path, const char *name, void *value, size_t size)
{
  //printf("getxattr [%s] [%s]\n", path, name);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_lgetxattr == NULL) {
    old_lgetxattr = dlsym(RTLD_NEXT, "getxattr");
  }
  //printf("Normakised getxattr [%s] [%s]\n", norm_path, name);
  return old_lgetxattr(norm_path, name, value, size);

}

int lgetxattr(const char *path, const char *name, void *value, size_t size)
{
  //printf("lgetxattr [%s] [%s]\n", path, name);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_lgetxattr == NULL) {
    old_lgetxattr = dlsym(RTLD_NEXT, "lgetxattr");
  }
  //printf("Normakised lgetxattr [%s] [%s]\n", norm_path, name);
  return old_lgetxattr(norm_path, name, value, size);

}

int listxattr(const char *path, char *list, size_t size)
{
  //printf("listxattr [%s]\n", path);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_listxattr == NULL) {
    old_listxattr = dlsym(RTLD_NEXT, "listxattr");
  }
  //printf("Normalised listxattr [%s]", norm_path);
  return old_listxattr(norm_path, list, size);

}

int llistxattr(const char *path, char *list, size_t size)
{
  //printf("llistxattr [%s]\n", path);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_llistxattr == NULL) {
    old_llistxattr = dlsym(RTLD_NEXT, "llistxattr");
  }
  //printf("Normalised llistxattr [%s]", norm_path);
  return old_llistxattr(norm_path, list, size);

}

int unlink(const char *path)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_unlink == NULL ) {
    old_unlink = dlsym(RTLD_NEXT, "unlink");
  }

  //printf("unlink %s\n", path);
  //path = norm_path;
  return old_unlink(norm_path);
}

int rename(const char *oldpath, const char *newpath)
{
  char *project = getenv("TASK_DIR");
  char src_norm_path[strlen(project) + strlen(oldpath) + 13];
  char dest_norm_path[strlen(project) + strlen(newpath) + 13];
  normalise_path(project, oldpath, src_norm_path);
  normalise_path(project, newpath, dest_norm_path);
  if ( old_rename == NULL ) {
    old_rename= dlsym(RTLD_NEXT, "rename");
  }

  //printf("rename %s %s\n", src_norm_path, dest_norm_path);
  //path = norm_path;
  return old_rename(src_norm_path, dest_norm_path);
}

int access(const char *path, int mode)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_access == NULL ) {
    old_access = dlsym(RTLD_NEXT, "access");
  }

  //printf("access %s\n", norm_path);
  path = norm_path;
  return old_access(norm_path, mode);
}

int __xstat(int ver, const char *path, struct stat *buf)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_xstat == NULL ) {
    old_xstat = dlsym(RTLD_NEXT, "__xstat");
  }

  //printf("xstat %s\n", norm_path);
  path = norm_path;
  return old_xstat(ver, norm_path, buf);

}

int __lxstat(int ver, const char *path, struct stat *buf)
{
  //printf("lstat [%s]\n", path);
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_lxstat == NULL ) {
    old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
  }

  //printf("lxstat normalised [%s]\n", norm_path);
  path = norm_path;
  return old_lxstat(ver, norm_path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_xstat64 == NULL ) {
    old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
  }

  //printf("xstat64 %s\n", norm_path);
  path = norm_path;
  return old_xstat64(ver, norm_path, buf);
}

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
  char *project = getenv("TASK_DIR");
  char norm_path[strlen(project) + strlen(path) + 13];
  normalise_path(project, path, norm_path);
  if ( old_lxstat64 == NULL ) {
    old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
  }

  //printf("lxstat64 %s\n", norm_path);
  path = norm_path;
  return old_lxstat64(ver, norm_path, buf);
}

/*
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t (*lfwrite)(const void *, size_t, size_t, FILE*) = dlsym(RTLD_NEXT, "fwrite");
    char *fname = recover_filename(stream);
    //printf("Write to file %s\n", fname);
    free(fname);
    return lfwrite(ptr, size, nmemb, stream);
}
*/
