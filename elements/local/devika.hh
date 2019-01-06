#ifndef CLICK_DEVIKA_HH
#define CLICK_DEVIKA_HH
#include "elements/ip/iprewriterbase.hh"
#include "elements/ip/iprwmapping.hh"
#include <click/sync.hh>
CLICK_DECLS

#define HASH_ENTRIES 16
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif


class devika : public IPRewriterBase { public:

    class UDPFlow : public IPRewriterFlow { public:

	UDPFlow(IPRewriterInput *owner, const IPFlowID &flowid,
		const IPFlowID &rewritten_flowid, int ip_p,
		bool guaranteed, click_jiffies_t expiry_j)
	    : IPRewriterFlow(owner, flowid, rewritten_flowid,
			     ip_p, guaranteed, expiry_j) {
	}

	bool streaming() const {
	    return _tflags > 6;
	}

	void apply(WritablePacket *p, bool direction, unsigned annos);

    };

    devika() CLICK_COLD;
    ~devika() CLICK_COLD;

    const char *class_name() const		{ return "devika"; }
    void *cast(const char *);

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    IPRewriterEntry *add_flow(int ip_p, const IPFlowID &flowid,
			      const IPFlowID &rewritten_flowid, int input);
    void destroy_flow(IPRewriterFlow *flow);
    click_jiffies_t best_effort_expiry(const IPRewriterFlow *flow) {
	return flow->expiry() + udp_flow_timeout(static_cast<const UDPFlow *>(flow)) -
               _timeouts[click_current_cpu_id()][1];
    }

    void push(int, Packet *);
#if HAVE_BATCH
    void push_batch(int port, PacketBatch *batch);
#endif

    void add_handlers() CLICK_COLD;

  private:
    per_thread<SizedHashAllocator<sizeof(UDPFlow)>> _allocator;

    unsigned _annos;
    uint32_t _udp_streaming_timeout;




    int DEBUG=1;
    struct ipv4_5tuple {
        in_addr ip_dst;
        in_addr ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));

    struct ipv4_and_port {
        in_addr ip;
        uint16_t port;
    };

    typedef struct rte_hash lookup_struct_t;
    lookup_struct_t *inside_lookup_struct;
    lookup_struct_t *outside_lookup_struct;

    struct ipv4_and_port inside_table[HASH_ENTRIES];
    struct ipv4_and_port outside_table[HASH_ENTRIES];
    
    int process(int port, Packet *p_in);

    int udp_flow_timeout(const UDPFlow *mf) const {
	if (mf->streaming())
	    return _udp_streaming_timeout;
	else
	    return _timeouts[click_current_cpu_id()][0];
    }

    static String dump_mappings_handler(Element *, void *);

    friend class IPRewriter;

};


inline void
devika::destroy_flow(IPRewriterFlow *flow)
{
    unmap_flow(flow, _map[click_current_cpu_id()]);
    flow->~IPRewriterFlow();
    _allocator->deallocate(flow);
}

CLICK_ENDDECLS
#endif
