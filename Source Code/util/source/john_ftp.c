#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <sys/_iovec.h>
#include <sys/mount.h>

/**
 * Data structure that captures the current state of a client.
 **/
 typedef struct ftp_env {
    int  data_fd;
    int  active_fd;
    int  passive_fd;
    char cwd[PATH_MAX];
  
    char type;
    off_t data_offset;
    char rename_path[PATH_MAX];
    struct sockaddr_in data_addr;
  } ftp_env_t;
  
  
  /**
   * Callback function prototype for ftp commands.
   **/
  typedef int (ftp_command_fn_t)(ftp_env_t* env, const char* arg);
  
  
  /**
   * Standard FTP commands.
   **/
  int ftp_cmd_APPE(ftp_env_t *env, const char* arg);
  int ftp_cmd_CDUP(ftp_env_t *env, const char* arg);
  int ftp_cmd_CWD (ftp_env_t *env, const char* arg);
  int ftp_cmd_DELE(ftp_env_t *env, const char* arg);
  int ftp_cmd_LIST(ftp_env_t *env, const char* arg);
  int ftp_cmd_MKD (ftp_env_t *env, const char* arg);
  int ftp_cmd_NOOP(ftp_env_t *env, const char* arg);
  int ftp_cmd_PASV(ftp_env_t *env, const char* arg);
  int ftp_cmd_PORT(ftp_env_t *env, const char* arg);
  int ftp_cmd_PWD (ftp_env_t *env, const char* arg);
  int ftp_cmd_QUIT(ftp_env_t *env, const char* arg);
  int ftp_cmd_REST(ftp_env_t *env, const char* arg);
  int ftp_cmd_RETR(ftp_env_t *env, const char* arg);
  int ftp_cmd_RMD (ftp_env_t *env, const char* arg);
  int ftp_cmd_RNFR(ftp_env_t *env, const char* arg);
  int ftp_cmd_RNTO(ftp_env_t *env, const char* arg);
  int ftp_cmd_SIZE(ftp_env_t *env, const char* arg);
  int ftp_cmd_STOR(ftp_env_t *env, const char* arg);
  int ftp_cmd_SYST(ftp_env_t *env, const char* arg);
  int ftp_cmd_TYPE(ftp_env_t *env, const char* arg);
  int ftp_cmd_USER(ftp_env_t *env, const char* arg);
  
  
  /**
   * Custom FTP commands.
   **/
  int ftp_cmd_KILL(ftp_env_t *env, const char* arg);
  int ftp_cmd_MTRW(ftp_env_t *env, const char* arg);
  int ftp_cmd_CHMOD(ftp_env_t *env, const char* arg);
  
  /**
   * Error responses to unknown/unavailable FTP commands.
   **/
  int ftp_cmd_unavailable(ftp_env_t *env, const char* arg);
  int ftp_cmd_unknown(ftp_env_t *env, const char* arg);


#define IOVEC_ENTRY(x) {x ? x : 0, \
			x ? strlen(x)+1 : 0}
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))


#ifdef __PROSPERO__
struct tm *localtime_s(const time_t *t, struct tm* tm);
#define LOCALTIME_R(t, tm) localtime_s(t, tm)
#else
#define LOCALTIME_R(t, tm) localtime_r(t, tm)
#endif


/**
 * Create a string representation of a file mode.
 **/
static void
ftp_mode_string(mode_t mode, char *buf) {
  char c, d;
  int i, bit;

  buf[10] = 0;
  for(i=0; i<9; i++) {
    bit = mode & (1<<i);
    c = i%3;
    if(!c && (mode & (1<<((d=i/3)+9)))) {
      c = "tss"[(int)d];
      if (!bit) c &= ~0x20;
    } else c = bit ? "xwr"[(int)c] : '-';
    buf[9-i] = c;
  }

  if (S_ISDIR(mode)) c = 'd';
  else if (S_ISBLK(mode)) c = 'b';
  else if (S_ISCHR(mode)) c = 'c';
  else if (S_ISLNK(mode)) c = 'l';
  else if (S_ISFIFO(mode)) c = 'p';
  else if (S_ISSOCK(mode)) c = 's';
  else c = '-';
  *buf = c;
}


/**
 * Open a new FTP data connection.
 **/
static int
ftp_data_open(ftp_env_t *env) {
  struct sockaddr_in data_addr;
  socklen_t addr_len;

  if(env->data_addr.sin_port) {
    if(connect(env->data_fd, (struct sockaddr*)&env->data_addr,
	       sizeof(env->data_addr))) {
      return -1;
    }
  } else {
    if((env->data_fd=accept(env->passive_fd, (struct sockaddr*)&data_addr,
			    &addr_len)) < 0) {
      return -1;
    }
  }

  return 0;
}


/**
 * Transmit a formatted string via an existing data connection.
 **/
static int
ftp_data_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  len = strlen(buf);
  if(write(env->data_fd, buf, len) != len) {
    return -1;
  }

  return 0;
}


/**
 * Read data from an existing data connection.
 **/
static int
ftp_data_read(ftp_env_t *env, void *buf, size_t count) {
  return recv(env->data_fd, buf, count, 0);
}


/**
 * Close an existing data connection.
 **/
static int
ftp_data_close(ftp_env_t *env) {
  if(!close(env->data_fd)) {
    return 0;
  }
  return -1;
}


/**
 * Transmit a formatted string via an active connection.
 **/
static int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  len = strlen(buf);

  if(write(env->active_fd, buf, len) != len) {
    return -1;
  }

  return 0;
}


/**
 * Transmit an errno string via an active connection.
 **/
static int
ftp_perror(ftp_env_t *env) {
  char buf[255];

  if(strerror_r(errno, buf, sizeof(buf))) {
    strncpy(buf, "Unknown error", sizeof(buf));
  }

  return ftp_active_printf(env, "550 %s\r\n", buf);
}


/**
 * Resolve a path to its absolute path.
 **/
static void
ftp_abspath(ftp_env_t *env, char *abspath, const char *path) {
  char buf[PATH_MAX+1];

  if(path[0] != '/') {
    snprintf(buf, sizeof(buf), "%s/%s", env->cwd, path);
    strncpy(abspath, buf, PATH_MAX);
  } else {
    strncpy(abspath, path, PATH_MAX);
  }
}


/**
 * Enter passive mode.
 **/
int
ftp_cmd_PASV(ftp_env_t *env, const char* arg) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint32_t addr = 0;
  uint16_t port = 0;

  if(getsockname(env->active_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  if(env->passive_fd > 0) {
    close(env->passive_fd);
  }

  if((env->passive_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if(bind(env->passive_fd, (struct sockaddr*)&sockaddr, sockaddr_len) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(listen(env->passive_fd, 5) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }
  port = sockaddr.sin_port;

  return ftp_active_printf(env, "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu).\r\n",
			   (addr >> 0) & 0xFF,
			   (addr >> 8) & 0xFF,
			   (addr >> 16) & 0xFF,
			   (addr >> 24) & 0xFF,
			   (port >> 0) & 0xFF,
			   (port >> 8) & 0xFF);
}


/**
 * Change the working directory to its parent.
 **/
int
ftp_cmd_CDUP(ftp_env_t *env, const char* arg) {
  int pos = -1;

  for(size_t i=0; i<sizeof(env->cwd); i++) {
    if(!env->cwd[i]) {
      break;
    } else if(env->cwd[i] == '/') {
      pos = i;
    }
  }

  if(pos > 0) {
    env->cwd[pos] = '\0';
  }

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 *
 **/
int
ftp_cmd_CHMOD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  mode_t mode = 0;
  char* ptr;

  if(!arg[0] || !(ptr=strstr(arg, " "))) {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }

  mode = strtol(arg, 0, 8);
  ftp_abspath(env, pathbuf, ptr+1);

  if(chmod(pathbuf, mode)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 OK\r\n");
}


/**
 * Change the working directory.
 **/
int
ftp_cmd_CWD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: CWD <PATH>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 No such directory\r\n");
  }

  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 * Delete a given file.
 **/
int
ftp_cmd_DELE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: DELE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(remove(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 File deleted\r\n");
}


/**
 * Trasfer a list of files and folder.
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX+256+2];
  struct dirent *ent;
  const char *p = env->cwd;
  struct stat statbuf;
  char timebuf[20];
  char modebuf[20];
  struct tm tm;
  DIR *dir;

  if(arg[0] && arg[0] != '-') {
    p = arg;
  }

  if(!(dir=opendir(p))) {
    return ftp_perror(env);
  }

  if(ftp_data_open(env)) {
    return ftp_perror(env);
  }

  ftp_active_printf(env, "150 Opening data transfer\r\n");

  while((ent=readdir(dir))) {
    if(p[0] == '/') {
      snprintf(pathbuf, sizeof(pathbuf), "%s/%s", p, ent->d_name);
    } else {
      snprintf(pathbuf, sizeof(pathbuf), "/%s/%s/%s", env->cwd, p,
	       ent->d_name);
    }

    if(stat(pathbuf, &statbuf) != 0) {
      continue;
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    LOCALTIME_R((const time_t *)&(statbuf.st_ctim), &tm);
    strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", &tm);
    ftp_data_printf(env, "%s %lu %lu %lu %llu %s %s\r\n", modebuf,
		    statbuf.st_nlink, statbuf.st_uid, statbuf.st_gid,
		    statbuf.st_size, timebuf, ent->d_name);
  }

  if(ftp_data_close(env)) {
    int ret = ftp_perror(env);
    closedir(dir);
    return ret;
  }

  if(closedir(dir)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer complete\r\n");
}


/**
 * Create a new directory at a given path.
 **/
int
ftp_cmd_MKD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MKD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(mkdir(pathbuf, 0777)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory created\r\n");
}


/**
 * No operation.
 **/
int
ftp_cmd_NOOP(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "200 NOOP OK\r\n");
}


/**
 * Establish a data connection with client.
 **/
int
ftp_cmd_PORT(ftp_env_t *env, const char* arg) {
  uint8_t addr[6];
  uint64_t s_addr;
  uint16_t port;

  if(sscanf(arg, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
	    addr, addr+1, addr+2, addr+3, addr+4, addr+5) != 6) {
    return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
  }

  if((env->data_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  s_addr = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
  port = (addr[5] << 8) | addr[4];

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr.s_addr = s_addr;
  env->data_addr.sin_port = port;

  return ftp_active_printf(env, "200 PORT command successful.\r\n");
}


/**
 * Print working directory.
 **/
int
ftp_cmd_PWD(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "257 \"%s\"\r\n", env->cwd);
}


/**
 * Disconnect client.
 **/
int
ftp_cmd_QUIT(ftp_env_t *env, const char* arg) {
  ftp_active_printf(env, "221 Goodbye\r\n");
  return -1;
}


/**
 * Mark the offset to start from in a future file transer.
 **/
int
ftp_cmd_REST(ftp_env_t *env, const char* arg) {
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  env->data_offset = atol(arg);

  return ftp_active_printf(env, "350 REST OK\r\n");
}


/**
 * Retreive data from a given file.
 **/
int
ftp_cmd_RETR(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  uint8_t buf[PAGE_SIZE];
  struct stat st;
  int err = 0;
  int len;
  int fd;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 Not a file\r\n");
  }

  if((fd=open(pathbuf, O_RDONLY, 0)) < 0) {
    return ftp_active_printf(env, "550 %s\r\n", strerror(errno));
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    close(fd);
    return -1;
  }

  if(ftp_data_open(env)) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  while((len=read(fd, buf, sizeof(buf))) != 0) {
    if(len < 0 || len != write(env->data_fd, buf, len)) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return err;
    }
  }

  close(fd);

  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer completed\r\n");
}


/**
 * Remove a directory.
 **/
int
ftp_cmd_RMD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RMD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(rmdir(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory deleted\r\n");
}


/**
 * Specify a path that will later be renamed by the RNTO command.
 **/
int
ftp_cmd_RNFR(ftp_env_t *env, const char* arg) {
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNFR <PATH>\r\n");
  }

  ftp_abspath(env, env->rename_path, arg);
  if(stat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "350 Awaiting new name\r\n");
}


/**
 * Rename a path previously specified by the RNFR command.
 **/
int
ftp_cmd_RNTO(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNTO <PATH>\r\n");
  }

  if(stat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  ftp_abspath(env, pathbuf, arg);
  if(rename(env->rename_path, pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Path renamed\r\n");
}


/**
 * Obtain the size of a given file.
 **/
int
ftp_cmd_SIZE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "213 %"  PRIu64 "\r\n", st.st_size);
}


/**
 * Store recieved data in a given file.
 **/
int
ftp_cmd_STOR(ftp_env_t *env, const char* arg) {
  off_t off = env->data_offset;
  uint8_t readbuf[0x4000];
  char pathbuf[PATH_MAX];
  int err = 0;
  size_t len;
  int fd;

  env->data_offset = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if((fd=open(pathbuf, O_CREAT | O_WRONLY, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(lseek(fd, off, SEEK_CUR) < 0) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    close(fd);
    return -1;
  }

  if(ftp_data_open(env)) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  while((len=ftp_data_read(env, readbuf, sizeof(readbuf)))) {
    if(write(fd, readbuf, len) != len) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return err;
    }
    off += len;
  }

  if(ftruncate(fd, off)) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    return err;
  }

  close(fd);
  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Data transfer complete\r\n");
}


/**
 * Append to an existing file.
 **/
int
ftp_cmd_APPE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat statbuf;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: APPE <FILENAME>\r\n");
  }

  if(!env->data_offset) {
    ftp_abspath(env, pathbuf, arg);
    if(stat(pathbuf, &statbuf)) {
      return ftp_perror(env);
    }
    env->data_offset = statbuf.st_size;
  }

  return ftp_cmd_STOR(env, arg);
}


/**
 * Return system type.
 **/
int
ftp_cmd_SYST(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "215 UNIX Type: L8\r\n");
}


/**
 * Sets the transfer mode (ASCII or Binary).
 **/
int
ftp_cmd_TYPE(ftp_env_t *env, const char* arg) {
  switch(arg[0]) {
  case 'A':
  case 'I':
    env->type = arg[0];
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
  }

  return ftp_active_printf(env, "501 Invalid argument to TYPE\r\n");
}


/**
 * Authenticate user.
 **/
int
ftp_cmd_USER(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "230 User logged in\r\n");
}


/**
 * Custom command that terminates the server.
 **/
int
ftp_cmd_KILL(ftp_env_t *env, const char* arg) {
  puts("Server killed");
  exit(EXIT_SUCCESS);
  return -1;
}


/**
 * Unsupported command.
 **/
int
ftp_cmd_unavailable(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "502 Command not implemented\r\n");
}


/**
 * Unknown command.
 **/
int
ftp_cmd_unknown(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "502 Command not recognized\r\n");
}



/**
 * Remount read-only mount points with write permissions.
 **/
int
ftp_cmd_MTRW(ftp_env_t *env, const char* arg) {
  struct iovec iov_sys[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  struct iovec iov_sysex[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  if(syscall(SYS_nmount, iov_sys, IOVEC_SIZE(iov_sys), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  if(syscall(SYS_nmount, iov_sysex, IOVEC_SIZE(iov_sysex), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 /system and /system_ex remounted\r\n");
}


/**
 * Map names of commands to function entry points.
 **/
typedef struct ftp_command {
  const char       *name;
  ftp_command_fn_t *func;
} ftp_command_t;


/**
 * Lookup table for FTP commands.
 **/
static ftp_command_t commands[] = {
  {"APPE", ftp_cmd_APPE},
  {"CDUP", ftp_cmd_CDUP},
  {"CWD",  ftp_cmd_CWD},
  {"DELE", ftp_cmd_DELE},
  {"LIST", ftp_cmd_LIST},
  {"MKD",  ftp_cmd_MKD},
  {"NOOP", ftp_cmd_NOOP},
  {"PASV", ftp_cmd_PASV},
  {"PORT", ftp_cmd_PORT},
  {"PWD",  ftp_cmd_PWD},
  {"QUIT", ftp_cmd_QUIT},
  {"REST", ftp_cmd_REST},
  {"RETR", ftp_cmd_RETR},
  {"RMD",  ftp_cmd_RMD},
  {"RNFR", ftp_cmd_RNFR},
  {"RNTO", ftp_cmd_RNTO},
  {"SIZE", ftp_cmd_SIZE},
  {"STOR", ftp_cmd_STOR},
  {"SYST", ftp_cmd_SYST},
  {"TYPE", ftp_cmd_TYPE},
  {"USER", ftp_cmd_USER},

  // custom commands
  {"KILL", ftp_cmd_KILL},
  {"MTRW", ftp_cmd_MTRW},
  {"CHMOD", ftp_cmd_CHMOD},

  // duplicates that ensure commands are 4 bytes long
  {"XCUP", ftp_cmd_CWD},
  {"XMKD", ftp_cmd_MKD},
  {"XPWD", ftp_cmd_PWD},
  {"XRMD", ftp_cmd_RMD},

  // not yet implemnted
  {"XRCP", ftp_cmd_unavailable},
  {"XRSQ", ftp_cmd_unavailable},
  {"XSEM", ftp_cmd_unavailable},
  {"XSEN", ftp_cmd_unavailable},
};


/**
 * Number of FTP commands in the lookup table.
 **/
static int nb_ftp_commands = (sizeof(commands)/sizeof(ftp_command_t));


/**
 * Read a line from a file descriptor.
 **/
static char*
ftp_readline(int fd) {
  int bufsize = 1024;
  int position = 0;
  char *buffer_backup;
  char *buffer = calloc(bufsize, sizeof(char));
  char c;

  if(!buffer) {
    perror("malloc");
    return NULL;
  }

  while(1) {
    int len = read(fd, &c, 1);
    if(len == -1 && errno == EINTR) {
      continue;
    }

    if(len <= 0) {
      free(buffer);
      return NULL;
    }

    if(c == '\r') {
      buffer[position] = '\0';
      position = 0;
      continue;
    }

    if(c == '\n') {
      return buffer;
    }

    buffer[position++] = c;

    if(position >= bufsize) {
      bufsize += 1024;
      buffer_backup = buffer;
      buffer = realloc(buffer, bufsize);
      if(!buffer) {
	perror("realloc");
	free(buffer_backup);
	return NULL;
      }
    }
  }
}


/**
 * Execute an FTP command.
 **/
static int
ftp_execute(ftp_env_t *env, char *line) {
  char *sep = strchr(line, ' ');
  char *arg = strchr(line, 0);

  if(sep) {
    sep[0] = 0;
    arg = sep + 1;
  }

  for(int i=0; i<nb_ftp_commands; i++) {
    if(strcmp(line, commands[i].name)) {
      continue;
    }

    return commands[i].func(env, arg);
  }

  return ftp_cmd_unknown(env, arg);
}


/**
 * Greet a new FTP connection.
 **/
static int
ftp_greet(ftp_env_t *env) {
  char msg[0x100];
  size_t len;

  snprintf(msg, sizeof(msg),
	   "220-Welcome to ftpsrv.elf running on pid %d, compiled at %s %s\r\n",
	   getpid(), __DATE__, __TIME__);
  strncat(msg, "220 Service is ready\r\n", sizeof(msg)-1);

  len = strlen(msg);
  if(write(env->active_fd, msg, len) != len) {
    return -1;
  }

  return 0;
}


/**
 * Entry point for new FTP connections.
 **/
static void*
ftp_thread(void *args) {
  ftp_env_t env;
  bool running;
  char *line;
  char* cmd;

  env.data_fd     = -1;
  env.passive_fd  = -1;
  env.active_fd   = (int)(long)args;

  env.type        = 'A';
  env.data_offset = 0;

  strcpy(env.cwd, "/");
  memset(env.rename_path, 0, sizeof(env.rename_path));
  memset(&env.data_addr, 0, sizeof(env.data_addr));

  running = !ftp_greet(&env);

  while(running) {
    if(!(line=ftp_readline(env.active_fd))) {
      break;
    }

    cmd = line;
    if(!strncmp(line, "SITE ", 5)) {
      cmd += 5;
    }

    if(ftp_execute(&env, cmd)) {
      running = false;
    }

    free(line);
  }

  if(env.active_fd > 0) {
    close(env.active_fd);
  }

  if(env.passive_fd > 0) {
    close(env.passive_fd);
  }

  if(env.data_fd > 0) {
    close(env.data_fd);
  }

  pthread_exit(NULL);

  return NULL;
}


/**
 * Serve FTP on a given port.
 **/
static int
ftp_serve(uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  pthread_t trd;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  signal(SIGPIPE, SIG_IGN);

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }

    printf("Serving FTP on %s:%d (%s)\n", ip, port, ifa->ifa_name);
    ifaddr_wait = 0;
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    perror("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("listen");
    return -1;
  }

  addr_len = sizeof(client_addr);

  while(1) {
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      perror("accept");
      break;
    }

    pthread_create(&trd, NULL, ftp_thread, (void*)(long)connfd);
  }

  return close(srvfd);
}

/**
 * Launch payload.
 **/
void *start_j_ftp(void* args) {
  uint16_t port = 2121;

  printf("FTP server was compiled at %s %s\n", __DATE__, __TIME__);

  while(1) {
    ftp_serve(port);
    sleep(3);
  }

  return NULL;
}