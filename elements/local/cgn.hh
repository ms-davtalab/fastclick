#ifndef CLICK_CGN_HH
#define CLICK_CGN_HH
//#include <click/batchelement.hh>
#include <click/element.hh>
CLICK_DECLS

class CGN : public Element { public:

    CGN() CLICK_COLD;
	~CGN() CLICK_COLD;

    const char *class_name() const              { return "CGN"; }
    const char *port_count() const              { return PORTS_1_1; }
    const char *processing() const				{ return "a/a"; }

    //Packet *simple_action(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

    int process(int port, Packet *p_in);
};

CLICK_ENDDECLS
#endif