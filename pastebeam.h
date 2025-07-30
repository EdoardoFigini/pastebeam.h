/*******************************************************************************************
 *
 *     pastebeam.h - v1.0
 *     offers utitlities to communicate via the pastebeam protocol
 *
 *     Before #including
 *
 *        #define PB_IMPLEMENTATION
 *
 *     in the file where you want to have the implementation
 *
 * USAGE:
 *
 *     First of all connect to a pastebeam server:
 *
 *     - initialize the connection object
 *
 *       pb_conn_t con = { 0 };
 *
 *     - call pb_connect
 *
 *       pb_err_t pb_connect(const char* host, int port, pb_conn_t* con);
 *
 *     Once the connection is established, contact the server with one of the
 *     following functions:
 *
 *     - send one line and store it in the server with a unique ID
 *
 *       pb_err_t pb_post_line(pb_conn_t *con, const char* line, char** id);
 *
 *     ...  -> TODO
 *
 *     All pb_post_* functions return the ID of the file saved on the server thorugh
 *     char** id, must be freed by the caller once it's done using it.
 *
 *     pb_err_t is returned by pb_* functions that interact with the server.
 *     To get the string representation of the error returned, a helper function is
 *     provied:
 *
 *       const char* pb_err_to_string(pb_err_t err);
 *
 *
 *     You can define:
 *
 *     - PB_CHALLENGE_MAX_ITER to set the maximum number of iterations in the challenge.
 *       (default is 5*10^7)
 *
 *     - PB_BUFFER_SIZE to set the maximum buffer size the connection object will use
 *       for the recv buffer. (default is 1024)
 *
 * CREDITS:
 *
 *     Edoardo Figini - author
 *
 *
 * LICENSE:
 *
 *     MIT License
 *
 *     Copyright (c) 2025 Edoardo Figini
 *
 *     Permission is hereby granted, free of charge, to any person obtaining a copy
 *     of this software and associated documentation files (the "Software"), to deal
 *     in the Software without restriction, including without limitation the rights
 *     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *     copies of the Software, and to permit persons to whom the Software is
 *     furnished to do so, subject to the following conditions:
 *
 *     The above copyright notice and this permission notice shall be included in all
 *     copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *     SOFTWARE.
 *
 *******************************************************************************************/


#ifndef PASTEBEAM_H
#define PASTEBEAM_H

#ifdef __linux__
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#else
#error Platform not supported
#endif

#include <string.h>

#define PB_DEFAULT_PORT 6969

#ifndef PB_BUFFER_SIZE
#define PB_BUFFER_SIZE  1024
#endif

#ifndef PB_CHALLENGE_MAX_ITER
#define PB_CHALLENGE_MAX_ITER 5 * 10000000
#endif

#define PB_RETURN(con, x) return (con->last_error = x)
#define PB_CHECK_RESP_PREFIX(con, pre, err)                          \
  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; } \
  if (!starts_with(con->buf, pre)) {                                 \
    PB_RETURN(con, err);                                             \
  }
#define PB_B64_LEN(length) ((length + 2) / 3) * 4;
#define PB_CSTR_SIZEOF(s) (sizeof(s) - 1) // discard null character

typedef enum {
  PB_OK,
  PB_NOT_PASTEBEAM,
  PB_UNSUPPORTED,
  PB_FILE_OPEN_FAILED,
  PB_SOCK_CREATION_FAILED,
  PB_SEND_FAILED,
  PB_RECV_FAILED,
  PB_CONNECTION_REFUSED,
  PB_POST_FAILED,
  PB_CHALLENGE_FAILED,
  PB_TIMEOUT,
} pb_err_t;

typedef struct {
  const char* host;
  int port;
  pb_err_t last_error;
  char buf[PB_BUFFER_SIZE];
#ifdef __linux__
  int sockfd;
#endif
} pb_conn_t;

typedef struct {
  char* buffer;
  size_t size;
} pb_resp_t;

typedef struct {
  char* algoritm;
  int leading_zeros;
  char* b64_suffix;
} pb_challenge_t;

typedef struct {
  struct {
    char* buffer;
    size_t len;
  } *lines;
  size_t size;
} pb_content_t;

pb_err_t pb_connect(const char* host, int port, pb_conn_t* con);
pb_err_t pb_post_line(pb_conn_t *con, const char* line, char** id);

const char* pb_err_to_string(pb_err_t err);

#endif // !PASTEBEAM_H

#ifdef PB_IMPLEMENTATION

static int starts_with(const char* a, const char* b) {
  for (; *b; a++, b++) {
    if (*a != *b)
      return 0;
  }
  return 1;
}

const char* pb_err_to_string(pb_err_t err) {
  switch (err) {
    case PB_OK:                    return "PB_OK";
    case PB_NOT_PASTEBEAM:         return "PB_NOT_PASTEBEAM";
    case PB_UNSUPPORTED:           return "PB_UNSUPPORTED";
    case PB_FILE_OPEN_FAILED:      return "PB_FILE_OPEN_FAILED";
    case PB_SOCK_CREATION_FAILED:  return "PB_SOCK_CREATION_FAILED";
    case PB_SEND_FAILED:           return "PB_SEND_FAILED";
    case PB_RECV_FAILED:           return "PB_RECV_FAILED";
    case PB_CONNECTION_REFUSED:    return "PB_CONNECTION_REFUSED";
    case PB_POST_FAILED:           return "PB_POST_FAILED";
    case PB_CHALLENGE_FAILED:      return "PB_CHALLENGE_FAILED";
    case PB_TIMEOUT:               return "PB_TIMEOUT";
    default:                       return "invalid error";
  }
}

#ifdef __linux__

typedef FILE* file_t;

static void* platform_malloc(size_t size) {
  return malloc(size);
}

static file_t platform_file_open(const char* filename) {
  return fopen(filename, "r");
}

static size_t platform_file_get_size(file_t handle) {
  size_t size = 0;
  fseek(handle, 0L, SEEK_END);
  size = ftell(handle);
  fseek(handle, 0L, SEEK_SET);
  return size;
}

static size_t platform_file_read(file_t handle, char* buf, size_t size) {
  return fread(buf, sizeof(char), size, handle);
}

static void platform_file_close(file_t handle) {
  fclose(handle);
}

static pb_err_t platform_connect(pb_conn_t* con) {
  struct sockaddr_in servaddr = { 0 };
  
  con->sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (con->sockfd == -1) PB_RETURN(con, PB_SOCK_CREATION_FAILED);

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(con->host);
  servaddr.sin_port = htons(con->port);

  if (connect(con->sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr))) {
    PB_RETURN(con, PB_CONNECTION_REFUSED);
  }

  PB_RETURN(con, PB_OK);
}

static pb_err_t platform_recv(pb_conn_t* con, int* size) {
  memset(con->buf, 0, PB_BUFFER_SIZE);
  int _size = recv(con->sockfd, con->buf, PB_BUFFER_SIZE, 0);
  if(_size < 0) PB_RETURN(con, PB_RECV_FAILED);
  if (size) *size = _size;
  PB_RETURN(con, PB_OK);
}

static pb_err_t platform_send(pb_conn_t* con, const char* data, size_t size) {
  if(send(con->sockfd, data, size, 0) < 0) PB_RETURN(con, PB_SEND_FAILED);
  PB_RETURN(con, PB_OK);
}

static int do_sha256(char* data, size_t len, unsigned char* digest) {
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;
  unsigned int md_len = 0;
  int res = -1;

  md = EVP_sha256();
  if (md == NULL) return -1;

  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) return -1;

  if (!EVP_DigestInit_ex(mdctx, md, NULL))         goto cleanup;
  if (!EVP_DigestUpdate(mdctx, data, len))         goto cleanup;
  if (!EVP_DigestFinal_ex(mdctx, digest, &md_len)) goto cleanup;
  res = 0;

cleanup:
  EVP_MD_CTX_free(mdctx);
  return res;
}

static int gen_rand_prefix(char* prefix, size_t prefix_buf_size, size_t *prefix_len) {
  unsigned int rnd;
  unsigned char bytes[100] = { 0 };

  if(RAND_bytes((unsigned char*)&rnd, sizeof(rnd)) != 1) return -1;

  int length = 3 + (rnd % 98);
  if(RAND_bytes(bytes, length) != 1) return -1;

  int encoded_len = PB_B64_LEN(length);
  if (encoded_len == 0 || encoded_len > (int)prefix_buf_size) return -1;

  *prefix_len = EVP_EncodeBlock((unsigned char*)prefix, bytes, length);

  return 0;
}

#else

typedef HANDLE file_t;

// TODO: windows

#endif

// NOTE: content is already terminated with \r\n
static pb_err_t solve_challenge(pb_challenge_t* ch, char* content, size_t len, char* b64_prefix, size_t b64_prefix_size, size_t *b64_prefix_len) {
  int b64_suffix_len = strlen(ch->b64_suffix);
  unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
  char hexdigest[SHA256_DIGEST_LENGTH * 2] = { 0 };

  char* msg = NULL;
  size_t msg_len;


  for (size_t iter = 0; iter < PB_CHALLENGE_MAX_ITER; iter++) {
    // printf("%8zu / %d  ", iter, PB_CHALLENGE_MAX_ITER);
    if(gen_rand_prefix(b64_prefix, b64_prefix_size, b64_prefix_len) != 0) return PB_CHALLENGE_FAILED;

    msg_len = *b64_prefix_len + 2 + len + b64_suffix_len + 2;
    msg = platform_malloc(msg_len + 1);
 
    if (!msg) return PB_CHALLENGE_FAILED;
    sprintf(msg, "%.*s\r\n%.*s%s\r\n", (int)*b64_prefix_len, b64_prefix, (int)len, content, ch->b64_suffix);

    if(do_sha256(msg, msg_len, digest) != 0) return PB_CHALLENGE_FAILED;
    for (size_t i=0; i < SHA256_DIGEST_LENGTH; i++) {
      sprintf(&hexdigest[i * 2], "%02X", digest[i]);
    }
    // printf("digest: %.*s\r", SHA256_DIGEST_LENGTH * 2, hexdigest);

    int zeros = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH * 2; i++) {
      if (hexdigest[i] == '0') {
        zeros++;
      } else {
        break;
      }
    }
    free(msg);

    if (zeros >= ch->leading_zeros) {
      // printf("\ndigest: %.*s\n", SHA256_DIGEST_LENGTH * 2, hexdigest);
      return PB_OK;
    }
  }
  return PB_CHALLENGE_FAILED;
}

/**
 * Connect to a Pastebeam server.
 * @param host ip address of the server, null terminated
 * @param port server port
 * @param con  pb connection object, should be allocated by the caller
 * @return pb error type, should be handled by the user. PB_OK on success
*/
pb_err_t pb_connect(const char* host, int port, pb_conn_t* con) {
  con->host = host;
  con->port = port ? port : PB_DEFAULT_PORT;

  if (platform_connect(con) != PB_OK) { return con->last_error; }

  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (!starts_with(con->buf, "HI\r\n")) {
    PB_RETURN(con, PB_NOT_PASTEBEAM);
  }

  PB_RETURN(con, PB_OK);
}

/**
 * Send a single line to the server, will be saved as its own file
 * with a unique id.
 * Do not use this function in a loop to send multiple lines as a
 * single file, use pb_post_file instead
 * @param con  pb connection object (initialize with pb_connect)
 * @param line single line, null terminated.
 * @param id   pointer to the id assigned to the file on the server,
 *             should be freed by the caller.
 * @return pb error type, should be handled by the user. PB_OK on success
*/
pb_err_t pb_post_line(pb_conn_t *con, const char* line, char** id) {
  if(platform_send(con, "POST\r\n", PB_CSTR_SIZEOF("POST\r\n")) != PB_OK) return con->last_error;
  PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);

  size_t len = strlen(line);
  char *extended = platform_malloc(len + 2);
  memcpy(extended, line, len);
  extended[len]   = '\r';
  extended[len+1] = '\n';
  platform_send(con, extended, len+2);
  if(con->last_error != PB_OK) return con->last_error;

  // FIXME: leaking extended at each return;
  PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);
 
  if(platform_send(con, "SUBMIT\r\n", PB_CSTR_SIZEOF("SUBMIT\r\n")) != PB_OK) return con->last_error;

  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (!starts_with(con->buf, "CHALLENGE ")) {
    PB_RETURN(con, PB_POST_FAILED);
  }

  strtok(con->buf, " \r\n");
  pb_challenge_t challenge = {
    .algoritm = strtok(NULL, " \r\n"),
    .leading_zeros = atoi(strtok(NULL, " \r\n")),
    .b64_suffix = strtok(NULL, " \r\n"),
  };

  char b64_prefix[1024] = { 0 };
  size_t b64_prefix_len = 0;
  size_t b64_prefix_size = sizeof(b64_prefix);

  if (strcmp(challenge.algoritm, "sha256") == 0) {
    if(
      solve_challenge(
        &challenge,
        extended,
        len + 2,
        b64_prefix,
        b64_prefix_size,
        &b64_prefix_len
      ) != PB_OK)
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  } else {
    free(extended);
    PB_RETURN(con, PB_UNSUPPORTED);
  }
  free(extended);

  size_t message_len = PB_CSTR_SIZEOF("ACCEPTED ") + b64_prefix_len + 2;
  char* message = platform_malloc(message_len + 1);


  sprintf(message, "ACCEPTED %.*s\r\n", (int)b64_prefix_len, b64_prefix);

  if(platform_send(con, message, message_len) != PB_OK) return con->last_error;
  free(message);
  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (starts_with(con->buf, "TOO SLOW\r\n")) {
    PB_RETURN(con, PB_TIMEOUT);
  }
  if (!starts_with(con->buf, "SENT ")) {
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  }

  strtok(con->buf, " ");
  *id = strdup(strtok(NULL, " "));

  PB_RETURN(con, PB_OK);
}


// =============================================
// NOT WORKING YET
// =============================================

// NOTE: *id should be freed by the user
pb_err_t pb_post_file(pb_conn_t *con, const char* filename, char** id) {
  (void)id;
  char* buffer = NULL;
  file_t handle = NULL;
  size_t file_size = 0;

  handle = platform_file_open(filename);
  if (!handle) { PB_RETURN(con, PB_FILE_OPEN_FAILED); }
  file_size = platform_file_get_size(handle);
  buffer = platform_malloc(file_size);
  platform_file_read(handle, buffer, file_size);

  char** rows = NULL;
  size_t n_rows = 1;
  for(size_t i=0; i < file_size; i++) {
    if (buffer[i] == '\n') n_rows++;
  }

  rows = platform_malloc(sizeof(*rows) * n_rows);
  printf("%zu lines:", n_rows);

  rows[0] = buffer;
  for(size_t i=1; i < n_rows; i++) {
    char *newline_pos = strchr(rows[i-1], '\n');
    if (newline_pos) {
      *newline_pos = '\0';
      rows[i] = newline_pos + 1;
    }
  }
  // TODO: continue from here

  platform_file_close(handle);

  free(rows);
  free(buffer);

#if 0
  if(platform_send(con, "POST\r\n", PB_CSTR_SIZEOF("POST\r\n")) != PB_OK) return con->last_error;
  PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);

  size_t len = strlen(line);
  char *extended = platform_malloc(len + 2);
  memcpy(extended, line, len);
  extended[len]   = '\r';
  extended[len+1] = '\n';
  platform_send(con, extended, len+2);
  if(con->last_error != PB_OK) return con->last_error;

  // FIXME: leaking extended at each return;
  PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);
 
  if(platform_send(con, "SUBMIT\r\n", PB_CSTR_SIZEOF("SUBMIT\r\n")) != PB_OK) return con->last_error;

  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (!starts_with(con->buf, "CHALLENGE ")) {
    PB_RETURN(con, PB_POST_FAILED);
  }

  strtok(con->buf, " \r\n");
  pb_challenge_t challenge = {
    .algoritm = strtok(NULL, " \r\n"),
    .leading_zeros = atoi(strtok(NULL, " \r\n")),
    .b64_suffix = strtok(NULL, " \r\n"),
  };

  char b64_prefix[1024] = { 0 };
  size_t b64_prefix_len = 0;
  size_t b64_prefix_size = sizeof(b64_prefix);

  if (strcmp(challenge.algoritm, "sha256") == 0) {
    if(
      solve_challenge(
        &challenge,
        extended,
        len + 2,
        b64_prefix,
        b64_prefix_size,
        &b64_prefix_len
      ) != PB_OK)
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  } else {
    free(extended);
    PB_RETURN(con, PB_UNSUPPORTED);
  }
  free(extended);

  size_t message_len = PB_CSTR_SIZEOF("ACCEPTED ") + b64_prefix_len + 2;
  char* message = platform_malloc(message_len + 1);


  sprintf(message, "ACCEPTED %.*s\r\n", (int)b64_prefix_len, b64_prefix);

  if(platform_send(con, message, message_len) != PB_OK) return con->last_error;
  free(message);
  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (!starts_with(con->buf, "SENT ")) {
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  }

  strtok(con->buf, " ");
  *id = strdup(strtok(NULL, " "));
#endif
  PB_RETURN(con, PB_OK);
}


#endif // !PB_IMPLEMENTATION
