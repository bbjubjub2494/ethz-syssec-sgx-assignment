#include "App.h"
#include "Enclave_u.h"

#include "common.cpp"

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);
  sgx_enclave_id_t eid;
  /* Initialize the enclave */
  if (initialize_enclave(eid) < 0) {
    printf("Enclave initialization failed.\n");
    return -1;
  }
  printf("From App: Enclave creation success. \n");

  ipc_connect();

  sgx_status_t sgx_status;

  enclave_reset(eid, &sgx_status);
  if (sgx_status != SGX_SUCCESS) {
    print_error_message(sgx_status);
    return -1;
  }

  size_t buflen;
  char buf[BUFSIZ];
  while ((buflen = read(ipc_fd, buf, BUFSIZ)) > 0) {
    enclave_ipc_recv(eid, &sgx_status, buf, buflen);
    if (sgx_status != SGX_SUCCESS) {
      print_error_message(sgx_status);
      return -1;
    }
    EnclaveState state;
    sgx_status = enclave_state(eid, &state);
    if (sgx_status != SGX_SUCCESS) {
      print_error_message(sgx_status);
      return -1;
    }
    if (state == DONE || state == ERROR)
      break;
  }

  /* Destroy the enclave */
  sgx_destroy_enclave(eid);

  printf("From App: Enclave destroyed.\n");
  return 0;
}
