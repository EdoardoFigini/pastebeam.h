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
 *     - send file contents and store them in the server with a unique ID
 *
 *       pb_err_t pb_post_file(pb_conn_t *con, const char* filename, char** id);
 *
 *     - get file contents into a string
 *
 *       pb_err_t pb_get_str(pb_conn_t *con, const char* id, char** out);
 *
 *     - save file contents to local file
 *
 *       pb_err_t pb_get_file(pb_conn_t *con, const char* id);
 *       pb_err_t pb_get_file_with_name(pb_conn_t *con, const char* id, const char* filename);
 *
 *
 *     pb_err_t is returned by pb_* functions that interact with the server.
 *     To get the string representation of the error returned, a helper function is
 *     provied:
 *
 *       const char* pb_err_to_string(pb_err_t err);
 *
 *
 *     Memory management notes:
 *
 *     All pb_post_* functions return the ID of the file saved on the server thorugh
 *     char** id, must be freed by the caller once it's done using it.
 *
 *     pb_get_str returns the contents of the file saved on the server thorugh
 *     char** out, must be freed by the caller once it's done using it.
 *
 *
 *     You can define:
 *
 *     - PB_CHALLENGE_MAX_ITER to set the maximum number of iterations in the challenge.
 *       (default is 5 * 10_000_000)
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
  PB_FILE_WRITE_FAILED,
  PB_SOCK_CREATION_FAILED,
  PB_SEND_FAILED,
  PB_RECV_FAILED,
  PB_CONNECTION_REFUSED,
  PB_POST_FAILED,
  PB_CHALLENGE_FAILED,
  PB_GET_FAILED,
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

typedef struct {
  char* data;
  size_t size;
} pb_slice_t;

// ==============================
//   FUNCTION PROTOTYPES
// ==============================
pb_err_t pb_connect(const char* host, int port, pb_conn_t* con);
pb_err_t pb_post_file(pb_conn_t *con, const char* filename, char** id);
pb_err_t pb_get_str(pb_conn_t *con, const char* id, char** out);
pb_err_t pb_get_file(pb_conn_t *con, const char* id);
pb_err_t pb_get_file_with_name(pb_conn_t *con, const char* id, const char* filename);

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
    case PB_FILE_WRITE_FAILED:     return "PB_FILE_WRITE_FAILED";
    case PB_SOCK_CREATION_FAILED:  return "PB_SOCK_CREATION_FAILED";
    case PB_SEND_FAILED:           return "PB_SEND_FAILED";
    case PB_RECV_FAILED:           return "PB_RECV_FAILED";
    case PB_CONNECTION_REFUSED:    return "PB_CONNECTION_REFUSED";
    case PB_POST_FAILED:           return "PB_POST_FAILED";
    case PB_CHALLENGE_FAILED:      return "PB_CHALLENGE_FAILED";
    case PB_GET_FAILED:            return "PB_GET_FAILED";
    case PB_TIMEOUT:               return "PB_TIMEOUT";
    default:                       return "invalid error";
  }
}

#ifdef __linux__

typedef FILE* file_t;

static void* platform_malloc(size_t size) {
  return malloc(size);
}

static void platform_free(void* data) {
  free(data);
}

static file_t platform_file_open_read(const char* filename) {
  return fopen(filename, "r");
}

static file_t platform_file_open_write(const char* filename) {
  return fopen(filename, "w");
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

static size_t platform_file_write(file_t handle, char* buf, size_t size) {
  return fwrite(buf, sizeof(char), size, handle);
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

static int do_sha256(pb_slice_t *data, unsigned char* digest) {
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;
  unsigned int md_len = 0;
  int res = -1;

  if (!data || !data->data || !data->size || !digest) return -1;

  md = EVP_sha256();
  if (md == NULL) return -1;

  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) return -1;

  if (!EVP_DigestInit_ex(mdctx, md, NULL))              goto cleanup;
  if (!EVP_DigestUpdate(mdctx, data->data, data->size)) goto cleanup;
  if (!EVP_DigestFinal_ex(mdctx, digest, &md_len))      goto cleanup;
  res = 0;

cleanup:
  EVP_MD_CTX_free(mdctx);
  return res;
}

static int gen_rand_prefix(pb_slice_t *prefix) {
  unsigned int rnd;
  unsigned char bytes[100] = { 0 };

  if(RAND_bytes((unsigned char*)&rnd, sizeof(rnd)) != 1) return -1;

  int length = 3 + (rnd % 98);
  if(RAND_bytes(bytes, length) != 1) return -1;

  int encoded_len = PB_B64_LEN(length);
  if (encoded_len == 0) return -1;

  prefix->data = platform_malloc(encoded_len + 1);
  prefix->size = EVP_EncodeBlock((unsigned char*)prefix->data, bytes, length);
  if ((int)prefix->size != encoded_len) return -1;

  return 0;
}

#else

typedef HANDLE file_t;

// TODO: windows

#endif

pb_slice_t pb_slice_alloc(size_t size) {
  return (pb_slice_t){
    .data = platform_malloc(size + 1), // account for '\0'
    .size = size
  };
}

void pb_slice_free(pb_slice_t *s) {
  platform_free(s->data);
  s->data = NULL;
  s->size = 0;
}

// NOTE: content is already terminated with \r\n
static pb_err_t solve_challenge(pb_challenge_t* ch, pb_slice_t *content, pb_slice_t *b64_prefix) {
  int b64_suffix_len = strlen(ch->b64_suffix);
  unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
  char hexdigest[SHA256_DIGEST_LENGTH * 2] = { 0 };

  pb_slice_t msg = { 0 };

  for (size_t iter = 0; iter < PB_CHALLENGE_MAX_ITER; iter++) {
    if(gen_rand_prefix(b64_prefix) != 0) return PB_CHALLENGE_FAILED;

    msg = pb_slice_alloc(b64_prefix->size + 2 + content->size + b64_suffix_len + 2);
    if (!msg.data) return PB_CHALLENGE_FAILED;
 
    sprintf(msg.data, "%.*s\r\n%.*s%s\r\n", (int)b64_prefix->size, b64_prefix->data, (int)content->size, content->data, ch->b64_suffix);

    if(do_sha256(&msg, digest) != 0) return PB_CHALLENGE_FAILED;
    pb_slice_free(&msg);
    for (size_t i=0; i < SHA256_DIGEST_LENGTH; i++) {
      sprintf(&hexdigest[i * 2], "%02X", digest[i]);
    }

    int zeros = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH * 2; i++) {
      if (hexdigest[i] == '0') {
        zeros++;
      } else {
        break;
      }
    }

    if (zeros >= ch->leading_zeros) {
      return PB_OK;
    }
    pb_slice_free(b64_prefix);
  }
  return PB_CHALLENGE_FAILED;
}

/**
 * Connect to a Pastebeam server.
 * @param host ip address of the server, null terminated
 * @param port server port, if 0 will be set to `PB_DEFAULT_PORT`
 * @param con  pb connection object, should be allocated by the caller
 * @return pb error type, should be handled by the user. `PB_OK` on success.
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
 * Send the contents of a file to the server, will be saved with
 * a unique id.
 * @param con      pb connection object (initialize with pb_connect)
 * @param filename name of the file to post, null terminated.
 * @param id       pointer to the id assigned to the file on the server,
 *                 should be freed by the caller.
 * @return pb error type, should be handled by the user. `PB_OK` on success.
*/
pb_err_t pb_post_file(pb_conn_t *con, const char* filename, char** id) {
  pb_slice_t file_buf = { 0 };
  file_t handle = NULL;

  handle = platform_file_open_read(filename);
  if (!handle) { PB_RETURN(con, PB_FILE_OPEN_FAILED); }
  file_buf.size = platform_file_get_size(handle);
  file_buf = pb_slice_alloc(file_buf.size);
  platform_file_read(handle, file_buf.data, file_buf.size);

  char** rows = NULL;
  size_t n_rows = 0;
  for(size_t i=0; i < file_buf.size; i++) {
    if (file_buf.data[i] == '\n') n_rows++;
  }

  rows = platform_malloc(sizeof(*rows) * n_rows);

  rows[0] = file_buf.data;
  for(size_t i=0; i < n_rows; i++) {
    char *newline_pos = strchr(rows[i], '\n');
    if (newline_pos) {
      *newline_pos = '\0';
      if (i < n_rows -1 )
        rows[i + 1] = newline_pos + 1;
    }
  }

  if(platform_send(con, "POST\r\n", PB_CSTR_SIZEOF("POST\r\n")) != PB_OK) return con->last_error;
  PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);

  pb_slice_t content = pb_slice_alloc(file_buf.size + n_rows); // add 1 for each row (\r\n in place of \0)
  pb_slice_t cursor  = content;

  for(size_t i=0; i < n_rows && cursor.data <= (content.data + content.size); i++) {
    cursor.size = sprintf(cursor.data, "%s\r\n", rows[i]);
    platform_send(con, cursor.data, cursor.size);
    if(con->last_error != PB_OK) return con->last_error;
    PB_CHECK_RESP_PREFIX(con, "OK\r\n", PB_POST_FAILED);
    cursor.data += cursor.size;
  }
  pb_slice_free(&file_buf);
  platform_free(rows);

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

  pb_slice_t b64_prefix = { 0 };

  if (strcmp(challenge.algoritm, "sha256") == 0) {
    if(
      solve_challenge(
        &challenge,
        &content,
        &b64_prefix
      ) != PB_OK)
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  } else {
    pb_slice_free(&content);
    PB_RETURN(con, PB_UNSUPPORTED);
  }
  pb_slice_free(&content);

  pb_slice_t message = { 0 };
  message.size = PB_CSTR_SIZEOF("ACCEPTED ") + b64_prefix.size + 2;
  message.data = platform_malloc(message.size + 1);

  sprintf(message.data, "ACCEPTED %.*s\r\n", (int)b64_prefix.size, b64_prefix.data);

  pb_slice_free(&b64_prefix);

  if(platform_send(con, message.data, message.size) != PB_OK) return con->last_error;

  pb_slice_free(&message);

  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (!starts_with(con->buf, "SENT ")) {
    PB_RETURN(con, PB_CHALLENGE_FAILED);
  }

  strtok(con->buf, " ");
  *id = strdup(strtok(NULL, " "));

  platform_file_close(handle);


  PB_RETURN(con, PB_OK);
}

/**
 * Get the contents of a file through a string
 * @param con  pb connection object (initialize with pb_connect)
 * @param id   id assigned to the file on the server
 * @param out  pointer to the output string that will hold
 *             the data, should be freed by the user.
 * @return pb error type, should be handled by the user. `PB_OK` on success.
*/
pb_err_t pb_get_str(pb_conn_t *con, const char* id, char** out) {
  pb_slice_t msg = { 0 };
  char buf[128] = { 0 };
  msg.size = sprintf(buf, "GET %s\r\n", id);
  msg.data = buf;

  if(platform_send(con, msg.data, msg.size) != PB_OK) return con->last_error;
  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (starts_with(con->buf, "404")) {
    PB_RETURN(con, PB_GET_FAILED);
  }

  *out = strdup(con->buf);

  PB_RETURN(con, PB_OK);
}

/**
 * Get the contents of a file and save it in the current directory
 * with the `id` as the filename.
 * @param con pb connection object (initialize with pb_connect)
 * @param id  id assigned to the file on the server
 * @return pb error type, should be handled by the user. `PB_OK` on success.
*/
pb_err_t pb_get_file(pb_conn_t *con, const char* id) {
 PB_RETURN(con, pb_get_file_with_name(con, id, id));
}

/**
 * Get the contents of a file and save it locally with a user defined
 * path
 * @param con       pb connection object (initialize with pb_connect)
 * @param id        id assigned to the file on the server
 * @param filename  path of the file that will contain the data,
 *                  will be overwritten if already exists
 * @return pb error type, should be handled by the user. `PB_OK` on success.
*/
pb_err_t pb_get_file_with_name(pb_conn_t *con, const char* id, const char* filename) {
  pb_slice_t msg = { 0 };

  file_t handle = NULL;

  char buf[128] = { 0 };
  msg.size = sprintf(buf, "GET %s\r\n", id);
  msg.data = buf;

  if(platform_send(con, msg.data, msg.size) != PB_OK) return con->last_error;
  if (platform_recv(con, NULL) != PB_OK) { return con->last_error; }
  if (starts_with(con->buf, "404")) {
    PB_RETURN(con, PB_GET_FAILED);
  }

  handle = platform_file_open_write(filename);
  if (!handle) { PB_RETURN(con, PB_FILE_OPEN_FAILED); }
  if (platform_file_write(handle, con->buf, strlen(con->buf)) == 0) {
    PB_RETURN(con, PB_FILE_WRITE_FAILED);
  }

  PB_RETURN(con, PB_OK);
}

#endif // !PB_IMPLEMENTATION
