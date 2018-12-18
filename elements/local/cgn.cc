#include <click/config.h>
#include "cgn.hh"
CLICK_DECLS

CGN::CGN()
{
}

CGN::~CGN()
{
}

void
CGN::push(int, Packet *p)
{
    click_chatter("Received packet %d\n", p->length());
    return;
}

Packet *
CGN::pull(int)
{
    return 0;
}

int
CGN::process(int port, Packet *p)
{
	return 1;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CGN)