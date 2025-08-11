#include <stdio.h>
#include <stdlib.h>

#define PB_IMPLEMENTATION
#include "pastebeam.h"

int main() {
  pb_conn_t con = { 0 };
  if (pb_connect("127.0.0.1", PB_DEFAULT_PORT, &con) != PB_OK) {
    printf("Could not connect to server (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    return 1;
  }

  char* file_id = NULL;

  if(pb_post_file(&con, "test.txt", &file_id)) {
    printf("Could not send file (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    printf("server responded with `%s`.\n", con.buf);
    return 1;
  }

  printf("file id: %s\n", file_id);

  free(file_id);

  return 0;
}
