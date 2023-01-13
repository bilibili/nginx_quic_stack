// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack connection helper class.

#ifndef _NGINX_T_QUIC_CONNECTION_HELPER_H_
#define _NGINX_T_QUIC_CONNECTION_HELPER_H_

#include <sys/types.h>
#include <set>

#include "quic/core/quic_connection.h"
#include "quic/core/quic_default_packet_writer.h"
#include "quic/core/quic_packet_writer.h"
#include "quic/core/quic_packets.h"
#include "quic/core/quic_simple_buffer_allocator.h"
#include "quic/core/quic_time.h"
#include "quic/platform/api/quic_epoll.h"
#include "quic/platform/api/quic_stream_buffer_allocator.h"
#include "src/tQuicClock.hh"

namespace quic {
  class QuicRandom;
}

namespace nginx {

enum class QuicAllocator { SIMPLE, BUFFER_POOL };

class tQuicConnectionHelper : public quic::QuicConnectionHelperInterface {
 public:
  tQuicConnectionHelper(tQuicClock* clock, QuicAllocator allocator);
  tQuicConnectionHelper(const tQuicConnectionHelper&) = delete;
  tQuicConnectionHelper& operator=(const tQuicConnectionHelper&) = delete;
  ~tQuicConnectionHelper() override;

  // QuicConnectionHelperInterface
  const quic::QuicClock* GetClock() const override;
  quic::QuicRandom* GetRandomGenerator() override;
  quic::QuicBufferAllocator* GetStreamSendBufferAllocator() override;

 private:
  const tQuicClock* clock_;
  quic::QuicRandom* random_generator_;
  // Set up allocators.  They take up minimal memory before use.
  // Allocator for stream send buffers.
  // TODO use nginx pool allocator
  quic::QuicStreamBufferAllocator stream_buffer_allocator_;
  quic::SimpleBufferAllocator simple_buffer_allocator_;
  QuicAllocator allocator_type_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_CONNECTION_HELPER_H_
