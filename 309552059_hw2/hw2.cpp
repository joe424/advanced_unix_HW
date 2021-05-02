#include <fstream>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

string argP, argO;
char* comm_arg[32];
int comm_arg_size;

static int (*old_chmod)(const char *, mode_t) = NULL;
int chmod(const char *pathname, mode_t mode) {
	if(old_chmod == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_chmod = (int (*)(const char*, mode_t))dlsym(handle, "chmod");
	}
    if(old_chmod == NULL){
        fprintf(stderr, "chmod() not found!\n");
        exit(1);
    }

    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    int ret = old_chmod(pathname, mode);
    int FD = atoi(getenv("FD"));
    if(exist == NULL) /* cannot resolve path */
        dprintf(FD, "[logger] chmod(\"%s\", %o) = %d\n", pathname, mode, ret);
    else
        dprintf(FD, "[logger] chmod(\"%s\", %o) = %d\n", path, mode, ret);
	return ret;
}

static int (*old_chown)(const char *, uid_t, gid_t) = NULL;
int chown(const char *pathname, uid_t owner, gid_t group) {
	if(old_chown == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_chown = (int (*)(const char *, uid_t, gid_t))dlsym(handle, "chown");
	}
    if(old_chown == NULL){
        fprintf(stderr, "chown() not found!\n");
        exit(1);
    }

    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    int ret = old_chown(pathname, owner, group);
    int FD = atoi(getenv("FD"));
    if(exist == NULL)/* cannot resolve path */
        dprintf(FD, "[logger] chown(\"%s\", %d, %d) = %d\n", pathname, owner, group, ret);
    else
        dprintf(FD, "[logger] chown(\"%s\", %d, %d) = %d\n", path, owner, group, ret);
	return ret;
}

static int (*old_close)(int) = NULL;
int close(int fd) {
	if(old_close == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_close = (int (*)(int))dlsym(handle, "close");
	}
    if(old_close == NULL){
        fprintf(stderr, "close() not found!\n");
        exit(1);
    }
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    int ret = old_close(fd);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] close(\"%s\") = %d\n", path, ret);
	return ret;
}

static int (*old_creat)(const char *, mode_t) = NULL;
int creat(const char *pathname, mode_t mode) {
	if(old_creat == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_creat = (int (*)(const char *, mode_t))dlsym(handle, "creat");
	}
    if(old_creat == NULL){
        fprintf(stderr, "creat() not found!\n");
        exit(1);
    }
    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    int ret = old_creat(pathname, mode);
    int FD = atoi(getenv("FD"));
    if(exist == NULL)/* cannot resolve path */
        dprintf(FD, "[logger] creat(\"%s\", %o) = %d\n", pathname, mode, ret);
    else
        dprintf(FD, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
	return ret;
}

static int (*old_fclose)(FILE *) = NULL;
int fclose(FILE *stream) {
	if(old_fclose == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_fclose = (int (*)(FILE *))dlsym(handle, "fclose");
	}
    if(old_fclose == NULL){
        fprintf(stderr, "fclose() not found!\n");
        exit(1);
    }
    int fd = fileno(stream);
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    int ret = old_fclose(stream);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] fclose(\"%s\") = %d\n", path, ret);
	return ret;
}

static FILE *(*old_fopen)(const char *, const char *) = NULL;
FILE *fopen(const char *pathname, const char *mode) {
	if(old_fopen == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_fopen = (FILE * (*)(const char *, const char *))dlsym(handle, "fopen");
	}
    if(old_fopen == NULL){
        fprintf(stderr, "fopen() not found!\n");
        exit(1);
    }
    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    FILE *ret = old_fopen(pathname, mode);
    int FD = atoi(getenv("FD"));
    if(exist == NULL)/* cannot resolve path */
        dprintf(FD, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, ret);
    else
        dprintf(FD, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
	return ret;
}

static size_t (*old_fread)(void *, size_t, size_t, FILE *) = NULL;
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	if(old_fread == NULL){
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_fread = (size_t (*)(void *, size_t, size_t, FILE *))dlsym(handle, "fread");
	}
    if(old_fread == NULL){
        fprintf(stderr, "fread() not found!\n");
        exit(1);
    }
    int fd = fileno(stream);
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    size_t ret = old_fread(ptr, size, nmemb, stream);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] fread(\"");
    for(int i=0; i<32; i++){
        if(((char*)ptr)[i] == '\0')
            break;
        else{
            if(isprint(((char*)ptr)[i]) != 0)
                dprintf(FD, "%c", ((char*)ptr)[i]);
            else
                dprintf(FD, ".");
        }
    }
    dprintf(FD, "\", %ld, %ld, \"%s\") = %ld\n", size, nmemb, path, ret);
	return ret;
}

static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	if(old_fwrite == NULL){
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_fwrite = (size_t (*)(const void *, size_t, size_t, FILE *))dlsym(handle, "fwrite");
	}
    if(old_fwrite == NULL){
        fprintf(stderr, "fwrite() not found!\n");
        exit(1);
    }
    int fd = fileno(stream);
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    size_t ret = old_fwrite(ptr, size, nmemb, stream);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] fwrite(\"");
    for(int i=0; i<32; i++){
        if(((char*)ptr)[i] == '\0')
            break;
        else{
            if(isprint(((char*)ptr)[i]) != 0)
                dprintf(FD, "%c", ((char*)ptr)[i]);
            else
                dprintf(FD, ".");
        }
    }
    dprintf(FD, "\", %ld, %ld, \"%s\") = %ld\n", size, nmemb, path, ret);
	return ret;
}

static int (*old_open)(const char *, int, ...) = NULL;
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if((flags & O_CREAT) != 0){ /* O_CREAT exist */
        va_list vl;
        va_start(vl, flags);
        mode = va_arg(vl, mode_t);
        va_end(vl);
    }
    
	if(old_open == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_open = (int (*)(const char*, int, ...))dlsym(handle, "open");
	}
    if(old_open == NULL){
        fprintf(stderr, "open() not found!\n");
        exit(1);
    }
    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    int ret = (mode != 0) ? old_open(pathname, flags, mode) : old_open(pathname, flags);
    int FD = atoi(getenv("FD"));
    if(exist == NULL) /* cannot resolve path */
        dprintf(FD, "[logger] open(\"%s\", %o, %o) = %d\n", pathname, flags, mode, ret);
    else
        dprintf(FD, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
	return ret;
}

static ssize_t (*old_read)(int, void *, size_t) = NULL;
ssize_t read(int fd, void *buf, size_t count) {
	if(old_read == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_read = (ssize_t (*)(int, void *, size_t))dlsym(handle, "read");
	}
    if(old_read == NULL){
        fprintf(stderr, "read() not found!\n");
        exit(1);
    }
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    ssize_t ret = old_read(fd, buf, count);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] read(\"%s\", \"", path);
    for(int i=0; i<32; i++){
        if(((char*)buf)[i] == '\0')
            break;
        else{
            if(isprint(((char*)buf)[i]) != 0)
                dprintf(FD, "%c", ((char*)buf)[i]);
            else
                dprintf(FD, ".");
        }
    }
    dprintf(FD, "\", %ld) = %ld\n", count, ret);
	return ret;
}

static int (*old_remove)(const char *) = NULL;
int remove(const char *pathname) {
	if(old_remove == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_remove = (int (*)(const char *))dlsym(handle, "remove");
	}
    if(old_remove == NULL){
        fprintf(stderr, "remove() not found!\n");
        exit(1);
    }
    char path[1024];
    char *exist;
    exist = realpath(pathname, path);
    int ret = old_remove(pathname);
    int FD = atoi(getenv("FD"));
    if(exist == NULL)/* cannot resolve path */
        dprintf(FD, "[logger] remove(\"%s\") = %d\n", pathname, ret);
    else
        dprintf(FD, "[logger] remove(\"%s\") = %d\n", path, ret);
	return ret;
}

static int (*old_rename)(const char *, const char *) = NULL;
int rename(const char *oldpath, const char *newpath) {
	if(old_rename == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_rename = (int (*)(const char *, const char *))dlsym(handle, "rename");
	}
    if(old_rename == NULL){
        fprintf(stderr, "rename() not found!\n");
        exit(1);
    }
    char path1[1024], path2[1024];
    char *exist1, *exist2;
    exist1 = realpath(oldpath, path1);
    exist2 = realpath(newpath, path2);
    int ret = old_rename(oldpath, newpath);
    int FD = atoi(getenv("FD"));
    if(exist1 == NULL)
        dprintf(FD, "[logger] rename(\"%s", oldpath);
    else
        dprintf(FD, "[logger] rename(\"%s", path1);
    if(exist2 == NULL)
        dprintf(FD, ", \"%s\") = %d\n", newpath, ret);
    else
        dprintf(FD, ", \"%s\") = %d\n", path2, ret);
	return ret;
}

static FILE *(*old_tmpfile)(void) = NULL;
FILE *tmpfile() {
	if(old_tmpfile == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_tmpfile = (FILE * (*)(void))dlsym(handle, "tmpfile");
	}
    if(old_tmpfile == NULL){
        fprintf(stderr, "tmpfile() not found!\n");
        exit(1);
    }
    FILE *ret = old_tmpfile();
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] tmpfile() = %p\n", ret);
	return ret;
}

static ssize_t (*old_write)(int, const void *, size_t) = NULL;
ssize_t write(int fd, const void *buf, size_t count) {
	if(old_write == NULL) {
		void *handle = dlopen("libc.so.6", RTLD_LAZY);
		if(handle != NULL)
			old_write = (ssize_t (*)(int, const void *, size_t))dlsym(handle, "write");
	}
    if(old_write == NULL){
        fprintf(stderr, "write() not found!\n");
        exit(1);
    }
    char path[128];
    memset(path, 0, 128);
    if((readlink(("/proc/self/fd/"+to_string(fd)).c_str(), path, 128)) == -1){
        fprintf(stderr, "readlink() failed!\n");
        exit(1);
    }
    ssize_t ret = old_write(fd, buf, count);
    int FD = atoi(getenv("FD"));
    dprintf(FD, "[logger] write(\"%s\", \"", path);
    for(int i=0; i<32; i++){
        if(((char*)buf)[i] == '\0')
            break;
        else{
            if(isprint(((char*)buf)[i]) != 0)
                dprintf(FD, "%c", ((char*)buf)[i]);
            else
                dprintf(FD, ".");
        }
    }
    dprintf(FD, "\", %ld) = %ld\n", count, ret);
	return ret;
}

void arg_parse(int argc, char *argv[]){
    if(argc == 1){
        fprintf(stderr, "no command given.\n");
        exit(0);
    }

    char *opt_arg[32];
    int db_dash = -1;
    for(int i=0; i<argc; i++){
        if((string)argv[i] == "--"){
            db_dash = i;
            break;
        }
        opt_arg[i] = argv[i];
    }

    if(argv[1][0] == '-'){
        int ch;
        int i = (db_dash == -1) ? argc : db_dash;
        for(int j=1; j<i; j++){
            if((string)argv[j] == "-p"){
                if(j+1 >= i){
                    dprintf(STDERR_FILENO, "no file specified!\n");
                    exit(0);
                }else
                    argP = (string)argv[j++ + 1];
            }
            else if((string)argv[j] == "-o"){
                if(j+1 >= i){
                    dprintf(STDERR_FILENO, "no file specified!\n");
                    exit(0);
                }else
                    argO = (string)argv[j++ + 1];
            }
            else if(argv[j][0] == '-' && strlen(argv[j]) == 2){
                dprintf(STDERR_FILENO, "%s: invalid option -- \'%c\'\n", argv[0], argv[j][1]);
                dprintf(STDERR_FILENO, "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                dprintf(STDERR_FILENO, "        -p: set the path to logger.so, default = ./logger.so\n");
                dprintf(STDERR_FILENO, "        -o: print output to file, print to \"stderr\" if no file specified\n");
                dprintf(STDERR_FILENO, "        --: separate the arguments for logger and for the command\n");
                exit(0);
            }else{
                dprintf(STDERR_FILENO, "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                dprintf(STDERR_FILENO, "        -p: set the path to logger.so, default = ./logger.so\n");
                dprintf(STDERR_FILENO, "        -o: print output to file, print to \"stderr\" if no file specified\n");
                dprintf(STDERR_FILENO, "        --: separate the arguments for logger and for the command\n");
                exit(0);
            }
        }

        if(db_dash != -1){
            int i;
            for(i=db_dash+1; i<=argc; i++)
                comm_arg[i-db_dash-1] = (i != argc) ? argv[i] : NULL;
            comm_arg_size = i-db_dash-1;
        }
    }else{
        int j = (db_dash == -1) ? 0 : db_dash;
        int i;
        for(i=j+1; i<=argc; i++)
            comm_arg[i-j-1] = (i != argc) ? argv[i] : NULL;
        comm_arg_size = i-j-1;
    }

    if(!comm_arg_size || db_dash == argc-1){
        dprintf(STDERR_FILENO, "no command given.\n");
        exit(0);
    }
}

int main(int argc, char *argv[]){
    argP = argO = "";
    comm_arg_size = 0;
    int FD = STDERR_FILENO;

    arg_parse(argc, argv);

    argP = (argP == "") ? "./logger.so" : argP;
    setenv("LD_PRELOAD", argP.c_str(), 1);

    if(argO != ""){
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        old_open = (int (*)(const char*, int, ...))dlsym(handle, "open");
        if((FD = old_open(argO.c_str(), O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1){
            fprintf(stderr, "openfile \'%s\' failed!\n", argO.c_str());
            exit(1);
        }
    }
    setenv("FD", to_string(FD).c_str(), 1);

    pid_t pid = fork();
    if(pid == -1){
        fprintf(stderr, "fork() failed!\n");
        exit(1);
    }else if(pid == 0){
        if(execvp(comm_arg[0], comm_arg) == -1)
            fprintf(stderr, "execvp() failed!\n");
    }else{
        wait(NULL);
        if(argO != "")
            close(FD);
    }
}