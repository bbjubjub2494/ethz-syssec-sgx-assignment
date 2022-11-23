#pragma once

#include <memory>

#include "sgx_tcrypto.h"


const size_t IV_LEN = 16; // must be equal to block size (128 bits)

struct IpcPacket {
  const enum Type { HANDSHAKE, RECORD } type;
  void *to_void() {
    return this;
  }

protected:
  IpcPacket(Type type) : type(type) {}
};

struct IpcHandshakePacket : public IpcPacket {
  sgx_ec256_public_t sender_pk;
  IpcHandshakePacket(const sgx_ec256_public_t &sender_pk)
      : IpcPacket(HANDSHAKE), sender_pk(sender_pk) {}
};

struct IpcRecordPacket : public IpcPacket {
  uint8_t iv[IV_LEN];
  const uint32_t len;
  uint8_t ciphertext[];

protected:
  IpcRecordPacket(uint32_t len) : IpcPacket(RECORD), len(len) {}

public:
  static std::unique_ptr<IpcRecordPacket> make(uint32_t len) {
    IpcRecordPacket *pkt = (IpcRecordPacket *)malloc(sizeof *pkt + len);
    new (pkt) IpcRecordPacket(len);
    return std::unique_ptr<IpcRecordPacket>{pkt};
  }
  size_t size() const {
    return sizeof *this + len;
  }
};
