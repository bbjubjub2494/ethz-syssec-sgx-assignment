#!/bin/sh

set -x

. /home/syssec/sgxsdk/environment

make -C Enclave_A SGX_MODE=SIM
make -C Enclave_B SGX_MODE=SIM

(cd Enclave_A/ && ./app) &
(cd Enclave_B/ && ./app)
