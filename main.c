#include <stdio.h>
#include <stdlib.h>

#define PB_IMPLEMENTATION
#include "pastebeam.h"

int main() {
  pb_conn_t con = { 0 };
  if (pb_connect("127.0.0.1", 6969, &con) != PB_OK) {
    printf("Could not connect to server (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    return 1;
  }

  char* ciao_id = NULL;
  if (pb_post_line(&con, "ciao", &ciao_id) != PB_OK) {
    printf("Could not send line (%s: %d)\n", pb_err_to_string(con.last_error), con.last_error);
    printf("server responded with `%s`.\n", con.buf);
    return 1;
  }

  printf("file id: %s\n", ciao_id);

  free(ciao_id);

  return 0;
}
