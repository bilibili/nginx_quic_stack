#include <errno.h>
#include <sys/socket.h>

#include "quic/core/crypto/quic_random.h"
#include "quic/platform/api/quic_socket_address.h"

#include "src/tQuicConnectionHelper.hh"

using namespace quic;

namespace nginx {

tQuicConnectionHelper::tQuicConnectionHelper(
    tQuicClock* clock,
    QuicAllocator type)
    : clock_(clock),
      random_generator_(QuicRandom::GetInstance()),
      allocator_type_(type) {}

tQuicConnectionHelper::~tQuicConnectionHelper() = default;

const QuicClock* tQuicConnectionHelper::GetClock() const {
  return clock_;
}

QuicRandom* tQuicConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicBufferAllocator* tQuicConnectionHelper::GetStreamSendBufferAllocator() {
  if (allocator_type_ == QuicAllocator::BUFFER_POOL) {
    return &stream_buffer_allocator_;
  } else {
    QUICHE_DCHECK(allocator_type_ == QuicAllocator::SIMPLE);
    return &simple_buffer_allocator_;
  }
}

}  // namespace nginx
