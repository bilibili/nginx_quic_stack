#include <type_traits>
#include "quic/core/quic_arena_scoped_ptr.h"

#include "src/tQuicAlarmFactory.hh"

using namespace quic;


namespace nginx {

tQuicAlarmEventQueue::tQuicAlarmEventQueue() {}

tQuicAlarmEventQueue::~tQuicAlarmEventQueue() {
  CleanupTimeToAlarmCBMap();
}

void tQuicAlarmEventQueue::RegisterAlarm(
  int64_t timeout_time_in_us, AlarmCB* ac)
{
  QUICHE_DCHECK(ac != nullptr) << "Invalid AlarmCB";
  if (all_alarms_.find(ac) != all_alarms_.end()) {
    QUICHE_DCHECK(false) << "Alarm already exists";
    return;
  }

  auto alarm_iter = alarm_map_.insert(std::make_pair(timeout_time_in_us, ac));
  all_alarms_.insert(ac);
  ac->OnRegistration(alarm_iter, this);
}

void tQuicAlarmEventQueue::UnregisterAlarm(
  const AlarmRegToken& iterator_token)
{
  AlarmCB* cb = iterator_token->second;
  alarm_map_.erase(iterator_token);
  all_alarms_.erase(cb);
  cb->OnUnregistration();
}

tQuicAlarmEventQueue::AlarmRegToken tQuicAlarmEventQueue::ReregisterAlarm(
  tQuicAlarmEventQueue::AlarmRegToken iterator_token,
  int64_t timeout_time_in_us)
{
  AlarmCB* cb = iterator_token->second;
  alarm_map_.erase(iterator_token);
  return alarm_map_.emplace(timeout_time_in_us, cb);
}

int64_t tQuicAlarmEventQueue::NextAlarmTimeInUs()
{
  if (alarm_map_.empty()) {
    return 0;
  }
  return alarm_map_.begin()->first;
}

void tQuicAlarmEventQueue::CallTimeoutAlarms(int64_t now_in_us)
{
  if (now_in_us <= 0) {
    return;
  }

  TimeToAlarmCBMap::iterator erase_it;
  for (auto i = alarm_map_.begin(); i != alarm_map_.end();) {
    if (i->first > now_in_us) {
      break;
    }
    AlarmCB* cb = i->second;
    // Execute the OnAlarm() only if we did not register
    // it in this loop itself.
    const bool added_in_this_round =
        alarms_reregistered_and_should_be_skipped_.find(cb) !=
        alarms_reregistered_and_should_be_skipped_.end();
    if (added_in_this_round) {
      ++i;
      continue;
    }
    all_alarms_.erase(cb);
    const int64_t new_timeout_time_in_us = cb->OnAlarm();

    erase_it = i;
    ++i;
    alarm_map_.erase(erase_it);

    if (new_timeout_time_in_us > 0) {
      // We add to hash_set only if the new timeout is <= now_in_us.
      // if timeout is > now_in_us then we have no fear that this alarm
      // can be reexecuted in this loop, and hence we do not need to
      // worry about a recursive loop.
      if (new_timeout_time_in_us <= now_in_us) {
        alarms_reregistered_and_should_be_skipped_.insert(cb);
      }
      RegisterAlarm(new_timeout_time_in_us, cb);
    }
  }
  alarms_reregistered_and_should_be_skipped_.clear();
}

void tQuicAlarmEventQueue::CleanupTimeToAlarmCBMap()
{
  TimeToAlarmCBMap::iterator erase_it;
  for (auto i = alarm_map_.begin(); i != alarm_map_.end();) {
    i->second->OnShutdown(this);
    erase_it = i;
    ++i;
    alarm_map_.erase(erase_it);
  }
}

tQuicAlarmEvent::tQuicAlarmEvent()
  : registered_(false),
    eq_(nullptr)
{}

tQuicAlarmEvent::~tQuicAlarmEvent()
{
  UnregisterIfRegistered();
}

int64_t tQuicAlarmEvent::OnAlarm()
{
  registered_ = false;
  return 0;
}

void tQuicAlarmEvent::OnRegistration(
  const tQuicAlarmEventQueue::AlarmRegToken& token,
  tQuicAlarmEventQueue* eq)
{
  QUICHE_DCHECK_EQ(false, registered_);

  registered_ = true;
  token_      = token;
  eq_         = eq;
  
}

void tQuicAlarmEvent::OnUnregistration()
{
  registered_ = false;
}

void tQuicAlarmEvent::OnShutdown(tQuicAlarmEventQueue* /*eq*/)
{
  registered_ = false;
  eq_ = nullptr;
}

void tQuicAlarmEvent::UnregisterIfRegistered()
{
  if (!registered_) {
    return;
  }

  eq_->UnregisterAlarm(token_);
}

void tQuicAlarmEvent::ReregisterAlarm(int64_t timeout_time_in_us)
{
  QUICHE_DCHECK(registered_);
  token_ = eq_->ReregisterAlarm(token_, timeout_time_in_us);
}

tQuicAlarm::QuicAlarmImpl::QuicAlarmImpl(tQuicAlarm* alarm)
  : alarm_(alarm)
{}

int64_t tQuicAlarm::QuicAlarmImpl::OnAlarm()
{
  tQuicAlarmEvent::OnAlarm();
  alarm_->Fire();
  // Fire will take care of registering the alarm, if needed.
  return 0;
}

tQuicAlarm::tQuicAlarm(
  tQuicAlarmEventQueue* eq,
  quic::QuicArenaScopedPtr<QuicAlarm::Delegate> delegate)
  : QuicAlarm(std::move(delegate)),
    eq_(eq),
    alarm_impl_(this)
{
}

void tQuicAlarm::SetImpl()
{
  QUICHE_DCHECK(deadline().IsInitialized());
  eq_->RegisterAlarm(
    (deadline() - QuicTime::Zero()).ToMicroseconds(), &alarm_impl_);
}

void tQuicAlarm::CancelImpl()
{
  QUICHE_DCHECK(!deadline().IsInitialized());
  alarm_impl_.UnregisterIfRegistered();
}

void tQuicAlarm::UpdateImpl()
{
  QUICHE_DCHECK(deadline().IsInitialized());
  int64_t epoll_deadline = (deadline() - QuicTime::Zero()).ToMicroseconds();
  if (alarm_impl_.registered()) {
    alarm_impl_.ReregisterAlarm(epoll_deadline);
  } else {
    eq_->RegisterAlarm(epoll_deadline, &alarm_impl_);
  }
}

tQuicAlarmFactory::tQuicAlarmFactory()
    : alarm_evq_(new tQuicAlarmEventQueue)
{
}

tQuicAlarmFactory::~tQuicAlarmFactory() = default;

QuicAlarm* tQuicAlarmFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new tQuicAlarm(alarm_evq_.get(), QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> tQuicAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<tQuicAlarm>(alarm_evq_.get(), std::move(delegate));
  }
  return QuicArenaScopedPtr<QuicAlarm>(
      new tQuicAlarm(alarm_evq_.get(), std::move(delegate)));
}

tQuicAlarmEventQueue* tQuicAlarmFactory::quic_alarm_event_queue()
{
  return alarm_evq_.get();
}

}  // namespace nginx
