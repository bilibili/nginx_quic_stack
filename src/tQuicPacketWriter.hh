// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack packet writer class.

#ifndef _NGINX_T_QUIC_PACKET_WRITER_H_
#define _NGINX_T_QUIC_PACKET_WRITER_H_

#include <cstddef>

#include "quic/core/quic_packet_writer.h"
#include "quic/platform/api/quic_export.h"
#include "quic/platform/api/quic_socket_address.h"

namespace quic {
struct WriteResult;
}

namespace nginx {

class tQuicPacketWriter : public quic::QuicPacketWriter {
 public:
  explicit tQuicPacketWriter(int fd);
  tQuicPacketWriter(const tQuicPacketWriter&) = delete;
  tQuicPacketWriter& operator=(const tQuicPacketWriter&) = delete;
  ~tQuicPacketWriter() override;

  // QuicPacketWriter
  quic::WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const quic::QuicIpAddress& self_address,
                          const quic::QuicSocketAddress& peer_address,
                          quic::PerPacketOptions* options) override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  quic::QuicByteCount GetMaxPacketSize(
      const quic::QuicSocketAddress& peer_address) const override;
  bool SupportsReleaseTime() const override;
  bool IsBatchMode() const override;
  char* GetNextWriteLocation(const quic::QuicIpAddress& self_address,
                             const quic::QuicSocketAddress& peer_address) override;
  quic::WriteResult Flush() override;

  void set_fd(int fd) { fd_ = fd; }

 protected:
  void set_write_blocked(bool is_blocked);
  int fd() { return fd_; }

 private:
  int fd_;
  bool write_blocked_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_PACKET_WRITER_H_
