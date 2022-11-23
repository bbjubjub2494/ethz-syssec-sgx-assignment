#include <cstring>

const size_t PSK_LEN = 10;

struct Message {
  enum Type { AUTHENTICATION, CHALLENGE, RESPONSE } type;
  const uint8_t *data() const {
    return reinterpret_cast<const uint8_t *>(this);
  }
  static const Message *safe_cast(const uint8_t *data, size_t len);

protected:
  Message(Type type) : type(type) {}
  size_t data_size() const; // override me!
};

struct AuthenticationMessage : public Message {
  uint8_t psk[PSK_LEN];
  AuthenticationMessage(uint8_t psk[PSK_LEN]) : Message(AUTHENTICATION) {
    std::memcpy(this->psk, psk, PSK_LEN);
  }
  const size_t data_size() const {
    return sizeof *this;
  }
};

struct ChallengeMessage : public Message {
  const uint64_t challenge_id;
  const uint64_t a, b;
  ChallengeMessage(uint64_t challenge_id, uint64_t a, uint64_t b)
      : Message(CHALLENGE), challenge_id(challenge_id), a(a), b(b) {}
  const size_t data_size() const {
    return sizeof *this;
  }
};

struct ResponseMessage : public Message {
  const uint64_t challenge_id;
  const uint64_t c;
  ResponseMessage(uint64_t challenge_id, uint64_t c)
      : Message(RESPONSE), challenge_id(challenge_id), c(c) {}
  const size_t data_size() const {
    return sizeof *this;
  }
};

inline const Message *Message::safe_cast(const uint8_t *data, size_t len) {
  if (len < sizeof(Message))
    return nullptr;
  auto msg = reinterpret_cast<const Message *>(data);
  switch (msg->type) {
  case AUTHENTICATION:
    if (len < sizeof(AuthenticationMessage))
      return nullptr;
    break;
  case CHALLENGE:
    if (len < sizeof(ChallengeMessage))
      return nullptr;
    break;
  case RESPONSE:
    if (len < sizeof(ResponseMessage))
      return nullptr;
    break;
  default:
    return nullptr;
  }
  return msg;
}
