#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <pwd.h>
#include <unistd.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "App.h"
#include "Enclave_u.h"
#include "sgx_urts.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer "
           "Reference\" for more details.\n",
           ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  /* Call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL,
                           &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    return -1;
  }
  return 0;
}

static int ipc_fd = -1;

const char *ipc_path = "/tmp/syssec_sock";

static void ipc_connect() {
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  int r, fd;
  if (sock < 0) {
    perror("socket");
    exit(1);
  }
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, ipc_path);
  r = bind(sock, (sockaddr *)&addr, sizeof addr);
  if (r < 0 && errno == EADDRINUSE) {
    r = connect(sock, (sockaddr *)&addr, sizeof addr);
    if (r < 0) {
      perror("connect");
      exit(1);
    }
    fd = sock;
  } else if (r < 0) {
    perror("bind");
    exit(1);
  } else {
    r = listen(sock, 0);
    if (r < 0) {
      perror("listen");
      exit(1);
    }
    fd = r = accept(sock, NULL, 0);
    if (r < 0) {
      perror("accept");
      exit(1);
    }
    r = unlink(ipc_path);
    if (r < 0) {
      perror("unlink");
      exit(1);
    }
  }
  ipc_fd = fd;
}

/* OCall functions */
void ipc_send(const char *buf, size_t buflen) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  ssize_t r = write(ipc_fd, buf, buflen);
  if (r < 0) {
    perror("write");
    exit(1);
  } else if (r != (ssize_t)buflen) {
    fprintf(stderr, "short write: %zd < %zd", r, buflen);
    exit(1);
  }
}

void ocall_eputs(const char *errmsg) {
  fprintf(stderr, "%s\n", errmsg);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);
  /* Initialize the enclave */
  if (initialize_enclave() < 0) {
    printf("Enclave initialization failed.\n");
    return -1;
  }
  printf("From App: Enclave creation success. \n");
  printf("From App: Write your protocol here ... \n");

  ipc_connect();

  sgx_status_t sgx_status;

  enclave_reset(global_eid, &sgx_status);
  if (sgx_status != SGX_SUCCESS) {
    print_error_message(sgx_status);
    return -1;
  }

  size_t buflen;
  char buf[BUFSIZ];
  while ((buflen = read(ipc_fd, buf, BUFSIZ)) > 0) {
    ipc_recv(global_eid, &sgx_status, buf, buflen);
  }

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  printf("From App: Enclave destroyed.\n");
  return 0;
}
