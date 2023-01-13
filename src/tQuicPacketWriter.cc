#include "net/quic/platform/impl/quic_socket_utils.h"
#include "src/tQuicPacketWriter.hh"

using namespace quic;

namespace nginx {

tQuicPacketWriter::tQuicPacketWriter(int fd)
    : fd_(fd), write_blocked_(false) {}

tQuicPacketWriter::~tQuicPacketWriter() = default;

WriteResult tQuicPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    PerPacketOptions* options) {
  DCHECK(!write_blocked_);
  DCHECK(nullptr == options)
      << "tQuicPacketWriter does not accept any options.";
  WriteResult result = QuicSocketUtils::WritePacket(fd_, buffer, buf_len,
                                                    self_address, peer_address);
  if (IsWriteBlockedStatus(result.status)) {
    write_blocked_ = true;
  }
  return result;
}

bool tQuicPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void tQuicPacketWriter::SetWritable() {
  write_blocked_ = false;
}

QuicByteCount tQuicPacketWriter::GetMaxPacketSize(
    const QuicSocketAddress& /*peer_address*/) const {
  return kMaxOutgoingPacketSize;
}

bool tQuicPacketWriter::SupportsReleaseTime() const {
  return false;
}

bool tQuicPacketWriter::IsBatchMode() const {
  return false;
}

char* tQuicPacketWriter::GetNextWriteLocation(
    const QuicIpAddress& /*self_address*/,
    const QuicSocketAddress& /*peer_address*/) {
  return nullptr;
}

WriteResult tQuicPacketWriter::Flush() {
  return WriteResult(WRITE_STATUS_OK, 0);
}

void tQuicPacketWriter::set_write_blocked(bool is_blocked) {
  write_blocked_ = is_blocked;
}

}  // namespace nginx
