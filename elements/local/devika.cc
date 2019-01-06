#include <click/config.h>
#include "devika.hh"
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/timer.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <rte_hash.h>
CLICK_DECLS

void
devika::UDPFlow::apply(WritablePacket *p, bool direction, unsigned annos)
{
    assert(p->has_network_header());
    click_ip *iph = p->ip_header();

    // IP header
    const IPFlowID &revflow = _e[!direction].flowid();
    iph->ip_src = revflow.daddr();
    iph->ip_dst = revflow.saddr();
    if (annos & 1)
	p->set_dst_ip_anno(revflow.saddr());
    if (direction && (annos & 2))
	p->set_anno_u8(annos >> 2, _reply_anno);
    update_csum(&iph->ip_sum, direction, _ip_csum_delta);

    // end if not first fragment
    if (!IP_FIRSTFRAG(iph))
	return;

    // TCP/UDP header
    click_udp *udph = p->udp_header();
    udph->uh_sport = revflow.dport(); // TCP ports in the same place
    udph->uh_dport = revflow.sport();
    if (iph->ip_p == IP_PROTO_TCP) {
	if (p->transport_length() >= 18)
	    update_csum(&reinterpret_cast<click_tcp *>(udph)->th_sum, direction, _udp_csum_delta);
    } else if (iph->ip_p == IP_PROTO_UDP) {
	if (p->transport_length() >= 8 && udph->uh_sum)
	    // 0 checksum is no checksum
	    update_csum(&udph->uh_sum, direction, _udp_csum_delta);
    }

    // track connection state
    if (direction)
	_tflags |= 1;
    if (_tflags < 6)
	_tflags += 2;
}

devika::devika() : _allocator()
{
}

devika::~devika()
{
}

void *
devika::cast(const char *n)
{
    if (strcmp(n, "IPRewriterBase") == 0)
	return (IPRewriterBase *)this;
    else if (strcmp(n, "devika") == 0)
	return (devika *)this;
    else
	return 0;
}

int
devika::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool dst_anno = true, has_reply_anno = false,
	has_udp_streaming_timeout, has_streaming_timeout;
    int reply_anno;
    uint32_t timeouts[2];
    timeouts[0] = 300;		// 5 minutes
    timeouts[1] = default_guarantee;

    if (Args(this, errh).bind(conf)
	.read("DST_ANNO", dst_anno)
	.read("REPLY_ANNO", AnnoArg(1), reply_anno).read_status(has_reply_anno)
	.read("UDP_TIMEOUT", SecondsArg(), timeouts[0])
	.read("TIMEOUT", SecondsArg(), timeouts[0])
	.read("UDP_STREAMING_TIMEOUT", SecondsArg(), _udp_streaming_timeout).read_status(has_udp_streaming_timeout)
	.read("STREAMING_TIMEOUT", SecondsArg(), _udp_streaming_timeout).read_status(has_streaming_timeout)
	.read("UDP_GUARANTEE", SecondsArg(), timeouts[1])
	.consume() < 0)
	return -1;

    for (unsigned i=0; i<_mem_units_no; i++) {
        _timeouts[i][0] = timeouts[0];
        _timeouts[i][1] = timeouts[1];
    }

    _annos = (dst_anno ? 1 : 0) + (has_reply_anno ? 2 + (reply_anno << 2) : 0);
    if (!has_udp_streaming_timeout && !has_streaming_timeout) {
        for (int i = 0; i < _mem_units_no; i++) {
            _udp_streaming_timeout = _timeouts[i][0];
        }
    }
    _udp_streaming_timeout *= CLICK_HZ; // IPRewriterBase handles the others


    //setup hash
    struct rte_hash_parameters ipv4_hash_params;
    /*{
        .name = NULL,
        .entries = HASH_ENTRIES,
        .key_len = sizeof(struct ipv4_5tuple),
        .hash_func = DEFAULT_HASH_FUNC,
        .hash_func_init_val = 0,
    };*/

    ipv4_hash_params.name = "inside_hash";
    ipv4_hash_params.entries = HASH_ENTRIES;
    ipv4_hash_params.key_len = sizeof(struct ipv4_5tuple);
    ipv4_hash_params.hash_func = DEFAULT_HASH_FUNC;
    ipv4_hash_params.hash_func_init_val = 0;
    ipv4_hash_params.socket_id = 0;
    inside_lookup_struct = rte_hash_create(&ipv4_hash_params);
    if (inside_lookup_struct == NULL)
        rte_exit(EXIT_FAILURE, "Unablea to create the inside hash on sockets %d\n", 1);

    ipv4_hash_params.name = "outside_hash";
    /*outside_lookup_struct = rte_hash_create(&ipv4_hash_params);
    if (outside_lookup_struct == NULL)
        rte_exit(EXIT_FAILURE, "Unablea to create the outside hash on sockets %d\n", 1);*/
    //end setup hash
    return IPRewriterBase::configure(conf, errh);
}

IPRewriterEntry *
devika::add_flow(int ip_p, const IPFlowID &flowid,
		      const IPFlowID &rewritten_flowid, int input)
{
    void *data = _allocator->allocate();
    if (!data)
        return 0;

    UDPFlow *flow = new(data) UDPFlow
	(&_input_specs[input], flowid, rewritten_flowid, ip_p,
	 !!_timeouts[click_current_cpu_id()][1], click_jiffies() +
         relevant_timeout(_timeouts[click_current_cpu_id()]));

    return store_flow(flow, input, _map[click_current_cpu_id()]);
}


int
devika::process(int port, Packet *p_in)
{
    printf("%s\n", "hello from cgn:D");

    WritablePacket *p = p_in->uniqueify();
    if (!p) {
        return -2;
    }

    click_ip *iph = p->ip_header();

    /* handle non-TCP and non-first fragments */
    int ip_p = iph->ip_p;
    if ((ip_p != IP_PROTO_TCP && ip_p != IP_PROTO_UDP && ip_p != IP_PROTO_DCCP)
	|| !IP_FIRSTFRAG(iph)
	|| p->transport_length() < 8) {
        const IPRewriterInput &is = _input_specs[port];
        if (is.kind == IPRewriterInput::i_nochange)
            return is.foutput;
        else
            return -1;
    }
    /* hash         */
    struct ipv4_5tuple myflow;
    myflow.ip_src = iph->ip_src;
    myflow.ip_dst = iph->ip_dst;
    myflow.proto = iph->ip_p;
    click_udp *udph = p->udp_header();
    //if (ip_p == IP_PROTO_UDP){
        myflow.port_src=udph->uh_sport;
        myflow.port_dst=udph->uh_dport;
    //}
    
    int ret;
    if(port==0){ /*do nat (from inside to outside)*/
        ret = rte_hash_lookup(inside_lookup_struct, (const void *)&myflow);
        if(ret<0){ /*first time to NAT*/
            /* TODO: allocate ip & port from pool*/
            in_addr public_ip;
            public_ip.s_addr = 3232236289; //192.168.3.1
            uint16_t public_port = udph->uh_sport;

            ret = rte_hash_add_key (inside_lookup_struct,
                        (void *) &myflow);
            if (ret < 0) {
                    rte_exit(EXIT_FAILURE, "Unable to add entry (inside)\n");
            }
            inside_table[ret].ip = public_ip;
            inside_table[ret].port = public_port;
            
            if(DEBUG){
                printf("FLOW>New flow add to inside db.@%d\n",ret);
            }

            
            myflow.ip_src = iph->ip_dst;
            myflow.ip_dst = public_ip;
            myflow.port_src = udph->uh_dport;
            myflow.port_dst = public_port;

            ret = rte_hash_add_key (outside_lookup_struct,
                        (void *) &myflow);
            if (ret < 0) {
                    rte_exit(EXIT_FAILURE, "Unable to add entry (outside)\n");
            }
            if(DEBUG){
                printf("FLOW>New flow add to outside db.@%d\n",ret);
            }
            outside_table[ret].ip = iph->ip_src;
            outside_table[ret].port = udph->uh_sport;

            /*change packet field*/
            iph->ip_src = public_ip;
            udph->uh_sport = public_port;
            iph->ip_sum = 0;
        }
    }
    else{/*undo nat (from outside to inside)*/

    }
    printf("%s\n", "return from cgn:D");
    return 0;
    /* end hash  */

    IPFlowID flowid(p);
    IPRewriterEntry *m = _map[click_current_cpu_id()].get(flowid);

    if (!m) {			// create new mapping
        IPRewriterInput &is = _input_specs.unchecked_at(port);
        IPFlowID rewritten_flowid = IPFlowID::uninitialized_t();

        int result = is.rewrite_flowid(flowid, rewritten_flowid, p);
        if (result == rw_addmap) {
            m = devika::add_flow(ip_p, flowid, rewritten_flowid, port);
        }

        if (!m) {
            return result;
        } else if (_annos & 2) {
            m->flow()->set_reply_anno(p->anno_u8(_annos >> 2));
        }
    }

    UDPFlow *mf = static_cast<UDPFlow *>(m->flow());
    mf->apply(p, m->direction(), _annos);

    click_jiffies_t now_j = click_jiffies();
    if (_timeouts[click_current_cpu_id()][1])
	mf->change_expiry(_heap[click_current_cpu_id()], true, now_j + _timeouts[click_current_cpu_id()][1]);
    else
	mf->change_expiry(_heap[click_current_cpu_id()], false, now_j + udp_flow_timeout(mf));

    printf("%d\n", m->output());
    return m->output();
}

void
devika::push(int port, Packet *p)
{
    int output_port = process(port, p);
    if (output_port < 0) {
        if (likely(output_port) == -1)
            p->kill();
        return;
    }

    checked_output_push(output_port, p);
}

#if HAVE_BATCH
void
devika::push_batch(int port, PacketBatch *batch)
{
    auto fnt = [this,port](Packet*p){return process(port,p);};
    CLASSIFY_EACH_PACKET(noutputs() + 1,fnt,batch,checked_output_push_batch);
}
#endif

String
devika::dump_mappings_handler(Element *e, void *)
{
    devika *rw = (devika *)e;
    click_jiffies_t now = click_jiffies();
    StringAccum sa;
    for (int i = 0; i < rw->_mem_units_no; i++) {
        for (Map::iterator iter = rw->_map[i].begin(); iter.live(); ++iter) {
            iter->flow()->unparse(sa, iter->direction(), now);
            sa << '\n';
        }
    }
    return sa.take_string();
}

void
devika::add_handlers()
{
    add_read_handler("table", dump_mappings_handler);
    add_read_handler("mappings", dump_mappings_handler, 0, Handler::h_deprecated);
    add_rewriter_handlers(true);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(IPRewriterBase)
EXPORT_ELEMENT(devika)
