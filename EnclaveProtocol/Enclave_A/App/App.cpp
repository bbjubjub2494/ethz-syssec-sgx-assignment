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
  printf("From App: Write your protocol here ... \n");

  ipc_connect();

  sgx_status_t sgx_status;

  enclave_reset(eid, &sgx_status);
  if (sgx_status != SGX_SUCCESS) {
    print_error_message(sgx_status);
    return -1;
  }

  size_t buflen;
  char buf[BUFSIZ];
  bool need_challenge = true;
  while ((buflen = read(ipc_fd, buf, BUFSIZ)) > 0) {
    enclave_ipc_recv(eid, &sgx_status, buf, buflen);
    if (need_challenge) {
      EnclaveState state;
      sgx_status = enclave_state(eid, &state);
      if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
      }
      printf("State: %d\n", state);
      if (state != READY)
        continue;
      enclave_issue_challenge(eid, &sgx_status);
      if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
      }
      need_challenge = false;
    }
  }

  /* Destroy the enclave */
  sgx_destroy_enclave(eid);

  printf("From App: Enclave destroyed.\n");
  return 0;
}
