#include "epoll_server/simple_epoll_server.h"
#include "quic/platform/api/quic_flag_utils.h"
#include "quic/platform/api/quic_flags.h"

#include "src/tQuicClock.hh"

using namespace quic;

namespace nginx {

tQuicClock::tQuicClock(tQuicClockTimeGenerator time_gen)
    : time_gen_(time_gen), largest_time_(QuicTime::Zero()) {}

tQuicClock::~tQuicClock() {}

QuicTime tQuicClock::ApproximateNow() const {
  return CreateTimeFromMicroseconds(time_gen_.ApproximateTimeNowInUsec());
}

QuicTime tQuicClock::Now() const {
  QuicTime now = CreateTimeFromMicroseconds(time_gen_.TimeNowInUsec());

  if (now <= largest_time_) {
    // Time not increasing, return |largest_time_|.
    return largest_time_;
  }

  largest_time_ = now;
  return largest_time_;
}

QuicWallTime tQuicClock::WallNow() const {
  return QuicWallTime::FromUNIXMicroseconds(
      time_gen_.ApproximateTimeNowInUsec());
}

QuicTime tQuicClock::ConvertWallTimeToQuicTime(
    const QuicWallTime& walltime) const {
  return QuicTime::Zero() +
         QuicTime::Delta::FromMicroseconds(walltime.ToUNIXMicroseconds());
}

}  // namespace nginx
