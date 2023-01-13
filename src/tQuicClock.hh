// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack clock class.

#ifndef _NGINX_T_QUIC_CLOCK_H_
#define _NGINX_T_QUIC_CLOCK_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "quic/core/quic_time.h"
#include "quic/core/quic_clock.h"
#include "src/quic_stack_api.h"

namespace nginx {

class tQuicClock : public quic::QuicClock {
 public:
  explicit tQuicClock(tQuicClockTimeGenerator time_gen);
  ~tQuicClock() override;

  // Returns the approximate current time as a QuicTime object.
  quic::QuicTime ApproximateNow() const override;

  // Returns the current time as a QuicTime object.
  // Note: this uses significant resources, please use only if needed.
  quic::QuicTime Now() const override;

  // Returns the current time as a QuicWallTime object.
  // Note: this uses significant resources, please use only if needed.
  quic::QuicWallTime WallNow() const override;

  // Override to do less work in this implementation.
  quic::QuicTime ConvertWallTimeToQuicTime(
      const quic::QuicWallTime& walltime) const override;

 protected:
  tQuicClockTimeGenerator time_gen_;
  // Largest time returned from Now() so far.
  mutable quic::QuicTime largest_time_;

 private:
  DISALLOW_COPY_AND_ASSIGN(tQuicClock);
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_CLOCK_H_
