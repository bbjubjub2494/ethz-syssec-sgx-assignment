#!/bin/bash

BASHRC_PATH="/home/syssec/.bashrc"
CURR_DIR=$(pwd)
SGX_BIN="sgx_linux_x64_sdk_2.15.100.3.bin"
SGX_INSTALLER_URL="https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.15.100.3.bin"
ENVIRONMENT_PATH="$CURR_DIR/sgxsdk/environment"
SSL_URL="http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb"
SSL_DEB="libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb"

wget $SSL_URL
sudo dpkg -i $SSL_DEB

sudo apt update
sudo apt install build-essential python2

if [ ! -f "$SGX_BIN" ]; then
	wget "$SGX_INSTALLER_URL"
	chmod +x "$SGX_BIN"
fi

echo "Installing SGX SDK..."
# echo yes to automatically install in current folder
yes yes | ./"$SGX_BIN" 2>&1 >/dev/null
echo "Installation complete!"


# This may leave some garbage lines at the end of your ~/.bashrc file if you install the SDK in different folders
# If you are getting a "bash: [..]/sgxsdk/environment: No such file or directory", this is likely the cause
# You will need to remove them manually
grep "source $ENVIRONMENT_PATH" "$BASHRC_PATH" || echo "source $ENVIRONMENT_PATH" >> $BASHRC_PATH

# Load the newly added environment variables
source $BASHRC_PATH
