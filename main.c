#include <stdio.h>
#include <stdlib.h>

#define PB_IMPLEMENTATION
#include "pastebeam.h"

int main() {
  // Initialize connection object and connect to pastebeam server
  pb_conn_t con = { 0 };
  if (pb_connect("127.0.0.1", PB_DEFAULT_PORT, &con) != PB_OK) {
    printf("Could not connect to server (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    return 1;
  }

  char* file_id = NULL;

  // Send the contents of `main.c` to the server, save id in `file_id`
  if(pb_post_file(&con, "main.c", &file_id)) {
    printf("Could not send file (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    printf("server responded with `%s`.\n", con.buf);
    return 1;
  }

  printf("file id: %s\n", file_id);

  // Reconnect
  // TODO: Understand if it is really necessary to reconnect
  if (pb_connect("127.0.0.1", PB_DEFAULT_PORT, &con) != PB_OK) {
    printf("Could not connect to server (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    return 1;
  }

  // Download the newly uploaded file to this current directory
  if(pb_get_file(&con, file_id)) {
    printf("Could not recieve file (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    printf("server responded with `%s`.\n", con.buf);
    return 1;
  }

  free(file_id);

  return 0;
}
