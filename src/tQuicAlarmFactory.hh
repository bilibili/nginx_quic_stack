// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack alarm factory class.

#ifndef _NGINX_T_QUIC_ALARM_FACTORY_H_
#define _NGINX_T_QUIC_ALARM_FACTORY_H_

#include <unordered_set>
#include "quic/core/quic_alarm.h"
#include "quic/core/quic_alarm_factory.h"
#include "quic/core/quic_one_block_arena.h"
#include "src/quic_stack_api.h"

namespace nginx {

class tQuicAlarmEvent;

class tQuicAlarmEventQueue {
public:
  typedef tQuicAlarmEvent                  AlarmCB;
  typedef std::multimap<int64_t, AlarmCB*> TimeToAlarmCBMap;
  typedef TimeToAlarmCBMap::iterator       AlarmRegToken;

public:
  tQuicAlarmEventQueue();
  virtual ~tQuicAlarmEventQueue();

  void RegisterAlarm(int64_t timeout_time_in_us, AlarmCB* ac);

  void UnregisterAlarm(const AlarmRegToken& iterator_token);

  AlarmRegToken ReregisterAlarm(
    AlarmRegToken iterator_token,
    int64_t timeout_time_in_us);

  int64_t NextAlarmTimeInUs();
  void CallTimeoutAlarms(int64_t now_in_us);

protected:
  void CleanupTimeToAlarmCBMap();

  struct AlarmCBHash {
    size_t operator()(AlarmCB* const& p) const {
      return reinterpret_cast<size_t>(p);
    }
  };

  using AlarmCBMap = std::unordered_set<AlarmCB*, AlarmCBHash>;

  AlarmCBMap       all_alarms_;
  AlarmCBMap       alarms_reregistered_and_should_be_skipped_;
  TimeToAlarmCBMap alarm_map_;
};

class tQuicAlarmEvent {
 public:
  tQuicAlarmEvent();
  virtual ~tQuicAlarmEvent();

  virtual int64_t OnAlarm();

  void OnRegistration(
    const tQuicAlarmEventQueue::AlarmRegToken& token,
    tQuicAlarmEventQueue* eq);

  void OnUnregistration();

  void OnShutdown(tQuicAlarmEventQueue* eq);

  void UnregisterIfRegistered();

  void ReregisterAlarm(int64_t timeout_time_in_us);

  bool registered() const { return registered_; }

  const tQuicAlarmEventQueue* event_queue() const { return eq_; }

 private:
  bool                                registered_;
  tQuicAlarmEventQueue::AlarmRegToken token_;
  tQuicAlarmEventQueue*               eq_;
};

class tQuicAlarm : public quic::QuicAlarm {
public:
  tQuicAlarm(
    tQuicAlarmEventQueue* eq,
    quic::QuicArenaScopedPtr<QuicAlarm::Delegate> delegate);

 protected:
  void SetImpl() override;
  void CancelImpl() override;
  void UpdateImpl() override;

private:
  class QuicAlarmImpl : public tQuicAlarmEvent {
  public:
    explicit QuicAlarmImpl(tQuicAlarm* alarm);

    int64_t OnAlarm() override;
  private:
    tQuicAlarm* alarm_;
  };

  tQuicAlarmEventQueue* eq_;
  QuicAlarmImpl         alarm_impl_;
};

class tQuicAlarmFactory : public quic::QuicAlarmFactory {
public:
  tQuicAlarmFactory();
  tQuicAlarmFactory(const tQuicAlarmFactory&) = delete;
  tQuicAlarmFactory& operator=(const tQuicAlarmFactory&) = delete;
  ~tQuicAlarmFactory() override;

  // QuicAlarmFactory interface.
  quic::QuicAlarm* CreateAlarm(quic::QuicAlarm::Delegate* delegate) override;
  quic::QuicArenaScopedPtr<quic::QuicAlarm> CreateAlarm(
      quic::QuicArenaScopedPtr<quic::QuicAlarm::Delegate> delegate,
      quic::QuicConnectionArena* arena) override;

  tQuicAlarmEventQueue* quic_alarm_event_queue();

private:
  std::unique_ptr<tQuicAlarmEventQueue> alarm_evq_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_ALARM_FACTORY_H_
