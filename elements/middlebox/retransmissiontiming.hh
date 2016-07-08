#ifndef MIDDLEBOX_RETRANSMISSIONTIMING_HH
#define MIDDLEBOX_RETRANSMISSIONTIMING_HH

#include <click/config.h>
#include <click/glue.hh>
#include <click/timer.hh>
#include <clicknet/tcp.h>
#include <click/timestamp.hh>

CLICK_DECLS

class TCPRetransmitter;

class RetransmissionTiming
{
public:
    RetransmissionTiming();
    ~RetransmissionTiming();

    void initTimer(struct fcb* fcb, TCPRetransmitter *retransmitter, TimerCallback f);
    bool isTimerInitialized();

    bool startRTTMeasure(uint32_t seq);
    bool signalAck(uint32_t ack);
    bool signalRetransmission(uint32_t expectedAck);
    bool isMeasureInProgress();

    bool startTimer();
    bool startTimeDoubleRTO();
    bool stopTimer();
    bool restartTimer();
    bool isTimerRunning();

private:
    // Retransmission timer
    Timer timer;

    bool measureInProgress;
    Timestamp measureStartTime;
    Timestamp measureEndTime;

    uint32_t rttSeq; // Sequence number that started the last measure of the RTT

    // Statistics about the retransmission timing
    // These variables are expressed in milliseconds
    uint32_t srtt;               // Smoothed Round-trip Time
    uint32_t rttvar;             // Round-trip time variation
    uint32_t rto;                // Retransmission TimeOut
    uint32_t clockGranularity;   // Smallest amount of time measurable

    const uint32_t K = 4;
    // (Jacobson, V., "Congestion Avoidance and Control")
    const float ALPHA = 1.0/8;
    const float BETA = 1.0/4;

    void computeClockGranularity();
    void checkRTOMinValue();
    void checkRTOMaxValue();
};

CLICK_ENDDECLS

#endif
