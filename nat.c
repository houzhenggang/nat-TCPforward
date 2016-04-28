#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unistd.h> // for close
#include "checksum.h"

#define PORT_SIZE 2001
#define PORT_OFFSET 10000
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
		struct nfq_data *pkt, void *cbData);
void checkTimestamp(int i);
int callback_tcp(struct nfq_q_handle *qh, int id, unsigned char* payload,
		int payloadLen);
int callback_udp(struct nfq_q_handle *qh, int id, unsigned char* payload,
		int payloadLen);

struct in_addr public_ip, internal_ip;
unsigned int subnet_mask;

struct handles {
	struct nfq_handle* h;
	struct nfnl_handle* nlh;
	struct nfq_q_handle *qh;
	int fd;
};

struct translation {
	u_int16_t external_port;
	u_int32_t internal_address;
	u_int16_t internal_port;
	u_int8_t protocol;
	time_t ts;
	int tcp_states;
	int valid;
};

int portRange[] = { 10000, 12000 };
struct translation table[PORT_SIZE];
int sockets[PORT_SIZE];
void consoleLog(char* msg) {
	printf("%s\n", msg);
}
int consoleError(char* msg) {
	consoleLog(msg);
	exit(1);
}

u_int16_t getSmallestAvailablePort() {
	struct sockaddr_in addr;
	//we try to bind the first avaiable port
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int i;
	for (i = 0; i < PORT_SIZE; i++) {
		addr.sin_port = htons(PORT_OFFSET + i);
		int ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
		if (ret != -1) {
			sockets[i] = fd;
			return PORT_OFFSET + i;
		}
	}
	consoleError("error: out of bounds\n");
	return -1;
}
void closePort(int fd) {
	if(fd > 0){
		printf("port %d will close\n",fd);
		close(fd);
	}
	consoleLog("close~\n");
}

/* bootstrap phase */
void bootstrap(struct handles* handles) {
	/**
	 * nfq Handle
	 */
	struct nfq_handle* h = nfq_open();
	if (!h) {
		consoleError("error: nfq_open\n");
	}
	handles->h = h;
	//consoleLog("un-binding existing nf_queue handler for AF_INET (if any)");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		consoleLog("error: nfq_unbind_pf\n");
	}

	//consoleLog("binding nfnetlink_queue as nf_queue handler for AF_INET");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		consoleError("error: nfq_bind_pf\n");
	}

	//consoleLog("binding this socket to queue '0'");
	struct nfq_q_handle* qh = nfq_create_queue(h, 0, &callback, NULL);
	if (!qh) {
		consoleError("error: nfq_create_queue\n");
	}
	handles->qh = qh;
	//consoleLog("nfq_set_mode = NFQNL_COPY_PACKET");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		consoleError("error: nfq_set_mode");
	}

	//bind the NFQUEUE handle with the socket handle
	struct nfnl_handle* nlh = nfq_nfnlh(h);
	handles->nlh = nlh;
	handles->fd = nfnl_fd(nlh);
}

int fourWayHandShake(struct tcphdr* tcph, int inbound, int i) {
	if (tcph->rst == 1) {
		table[i].tcp_states = 4;
	} else if (tcph->fin == 1 && table[i].tcp_states == 0) {
		table[i].tcp_states = inbound == 1 ? 1 : 11;
	} else if (table[i].tcp_states > 10) {
		//outbound first
		if (table[i].tcp_states == 11 && inbound == 1) {
			if (tcph->fin == 1 && tcph->ack == 1) {
				table[i].tcp_states = 13;
			} else if (tcph->ack == 1) {
				table[i].tcp_states = 12;
			}
		} else if (table[i].tcp_states == 12 && inbound == 1
				&& tcph->fin == 1) {
			table[i].tcp_states = 13;

		} else if (table[i].tcp_states == 13 && inbound == 0
				&& tcph->ack == 1) {
			table[i].tcp_states = 14;
		}
	} else {
		//inbound first
		if (table[i].tcp_states == 1 && inbound == 0) {
			if (tcph->fin == 1 && tcph->ack == 1) {
				table[i].tcp_states = 3;
			} else if (tcph->ack == 1) {
				table[i].tcp_states = 2;
			}
		} else if (table[i].tcp_states == 2 && inbound == 0
				&& tcph->fin == 1) {
			table[i].tcp_states = 3;

		} else if (table[i].tcp_states == 3 && inbound == 1
				&& tcph->ack == 1) {
			table[i].tcp_states = 4;
		}
	}
	printf("fourWayHandShake: %d\n", table[i].tcp_states);
	return table[i].tcp_states;
}

void dumpTCP(struct iphdr* ip, struct tcphdr* tcp) {
	struct in_addr sAddr, dAddr;
	char sAddr_str[INET_ADDRSTRLEN + 1], dAddr_str[INET_ADDRSTRLEN + 1];

	sAddr.s_addr = ip->saddr;
	dAddr.s_addr = ip->daddr;

	if (!inet_ntop(AF_INET, &sAddr, sAddr_str, INET_ADDRSTRLEN)) {
		consoleError("src addr error");
	}

	if (!inet_ntop(AF_INET, &dAddr, dAddr_str, INET_ADDRSTRLEN)) {
		consoleError("dest addr error");
	}

	printf("src addr: %s:%d dest addr: %s:%d\n", sAddr_str, ntohs(tcp->source),
			dAddr_str, ntohs(tcp->dest));

	printf("\tflag: ");
	fflush(stdout);
	if (tcp->urg)
		putchar('U');
	else
		putchar('_');

	if (tcp->ack)
		putchar('A');
	else
		putchar('_');

	if (tcp->psh)
		putchar('P');
	else
		putchar('_');

	if (tcp->rst)
		putchar('R');
	else
		putchar('_');

	if (tcp->syn)
		putchar('S');
	else
		putchar('_');

	if (tcp->fin)
		putchar('F');
	else
		putchar('_');
	printf("\tseq: %lu\tack: %lu\n", (unsigned long) ntohl(tcp->seq),
			(unsigned long) ntohl(tcp->ack_seq));
	fflush(stdout);
}

void dumpUDP(struct iphdr* ip, struct udphdr* udp) {
	struct in_addr sAddr, dAddr;
	char sAddr_str[INET_ADDRSTRLEN + 1], dAddr_str[INET_ADDRSTRLEN + 1];

	sAddr.s_addr = ip->saddr;
	dAddr.s_addr = ip->daddr;

	if (!inet_ntop(AF_INET, &sAddr, sAddr_str, INET_ADDRSTRLEN)) {
		consoleError("format error");
	}

	if (!inet_ntop(AF_INET, &dAddr, dAddr_str, INET_ADDRSTRLEN)) {
		consoleError("format error");
	}
	printf("src addr: %s:%d dest addr: %s:%d\n", sAddr_str, ntohs(udp->source),
			dAddr_str, ntohs(udp->dest));
	fflush(stdout);
}

/**
 * main phase's callback
 */
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
		struct nfq_data *pkt, void *cbData) {
	/**
	 * packet id
	 */
	unsigned int id = 0;
	struct nfqnl_msg_packet_hdr* header;

	printf("pkt_rcv: ");
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
		printf("id: %u\n", id);
		//printf("  hw_protocol: %u\n", ntohs(header->hw_protocol));
		//printf("  hook: %u\n", header->hook);
	}

	// print the timestamp (PC: seems the timestamp is not always set)
	struct timeval tv;
	if (!nfq_get_timestamp(pkt, &tv)) {
		printf("  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	} else {
		printf("  timestamp: nil\n");
	}
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (char**) &pktData);

	//IP Header
	struct iphdr* iph = (struct iphdr*) pktData;

	switch ((iph->protocol)) {
	case IPPROTO_ICMP:
		printf("icmp");
		break;
	case IPPROTO_TCP:
		dumpTCP(iph, (struct tcphdr *) (((char*) iph) + (iph->ihl << 2)));
		consoleLog("establish TCP connection");
		return callback_tcp(qh, id, pktData, len);
		break;
	case IPPROTO_UDP:
		dumpUDP(iph, (struct udphdr *) (((char*) iph) + (iph->ihl << 2)));
		//consoleLog("Call UDP");
		return callback_udp(qh, id, pktData, len);
		break;
	default:
		printf("unknown protocol");
	}
	return 0;
}

int callback_tcp(struct nfq_q_handle *qh, int id, unsigned char* payload,
		int payloadLen) {
	struct iphdr* iph = (struct iphdr*) payload;
	struct tcphdr* tcph = (struct tcphdr *) (((char*) iph) + (iph->ihl << 2));

	unsigned long sAddr = ntohl(iph->saddr);
	unsigned short sPort = ntohs(tcph->source);

	time_t ts = time(NULL);
	if ((ntohl(iph->saddr) & subnet_mask) == ntohl(internal_ip.s_addr)) {
		//outbound
		consoleLog("error: out of bounds");
		// search NAT table
		int i, found = -1, externalPort;

		for (i = 0; i < PORT_SIZE; i++) {
			if (table[i].valid == 0)
				continue;
			if (table[i].protocol == IPPROTO_TCP
					&& (table[i].internal_address == sAddr)
					&& (table[i].internal_port == sPort)) {
				table[i].ts = ts;
				externalPort = table[i].external_port;
				found = i;
				printf("%d\n", i);

			}
		}

		if (found == -1) {
			//not found
			if (tcph->syn == 1) {
				//3.1.b create if and only if not found and SYN
				consoleLog("not found and SYN");
				externalPort = getSmallestAvailablePort();
				i = externalPort - PORT_OFFSET;
				table[i].internal_address = ntohl(iph->saddr);
				table[i].internal_port = ntohs(tcph->source);
				table[i].ts = ts;
				table[i].protocol = IPPROTO_TCP;
				table[i].external_port = externalPort;
				table[i].tcp_states = 0;
				table[i].valid = 1;
			} else {
				//3.1.c not found and not SYN
				//DROP it
				consoleLog("not found and not SYN");
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		} else if (tcph->syn == 1) {
			//found and SYN packet
			//undefined
			consoleLog("found and SYN undefined action");
		}

		iph->saddr = public_ip.s_addr;
		// and the source port number with the translated port number
		tcph->source = htons(externalPort);

		///4-WAY handshake monitor begin
		int state = fourWayHandShake(tcph, 0, externalPort - PORT_OFFSET);

		if (state == 4 || state == 14) {
			consoleLog("fourWayHandShake ou of bounds end");
			table[externalPort - PORT_OFFSET].valid = 0;
			printf("external_port: %d socket: %d\n", externalPort, sockets[externalPort - PORT_OFFSET]);
			closePort(sockets[externalPort - PORT_OFFSET]);

		}
		///4-WAY handshake monitor end

		// NEED to modify fields of the IP and tcp headers
		iph->check = ip_checksum((unsigned char*) iph);
		tcph->check = tcp_checksum((unsigned char*) iph);
		
		consoleLog("reach");
		return nfq_set_verdict(qh, id, NF_ACCEPT, payloadLen,
				(unsigned char*) payload);
	} else {
		//inbound
		consoleLog("inbound");
		int i, found = -1;
		u_int16_t dest = ntohs(tcph->dest);
		for (i = 0; i < PORT_SIZE; i++) {
			if (table[i].valid == 0)
				continue;
			if (table[i].protocol == IPPROTO_TCP
					&& table[i].external_port == dest) {
				table[i].ts = ts;
				found = i;
				printf("found %d \n", i);
			}
		}

		if (found == -1) {
			//2.2.c If not found, the NAT program should drop the packet.
			consoleLog("not found, inbound pkt drop");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} else {
			//2.2.b If yes, the NAT program modifies the destination IP address and the destination
			//port number of the inbound packet, and sends it to the target VM.
			consoleLog("inbound pkt accept");
			iph->daddr = htonl(table[found].internal_address);
			tcph->dest = htons(table[found].internal_port);

			///4-WAY handshake monitor begin
			int state = fourWayHandShake(tcph, 1, found);

			if (state == 4 || state == 14) {
				consoleLog("inbound fourWayHandShake end");
				table[found].valid = 0;
				consoleLog("fourWayHandShake close port");
				closePort(sockets[dest - PORT_OFFSET]);

			}
			///4-WAY handshake monitor end

			iph->check = ip_checksum((unsigned char*) iph);
			tcph->check = tcp_checksum((unsigned char*) iph);
			return nfq_set_verdict(qh, id, NF_ACCEPT, payloadLen, payload);
		}

	}

}
int callback_udp(struct nfq_q_handle *qh, int id, unsigned char* payload,
		int payloadLen) {
	struct iphdr* iph = (struct iphdr*) payload;
	struct udphdr* udph = (struct udphdr *) (((char*) iph) + (iph->ihl << 2));

	unsigned long sAddr = ntohl(iph->saddr);
	unsigned short sPort = ntohs(udph->source);

	time_t ts = time(NULL);

	if ((ntohl(iph->saddr) & subnet_mask) == ntohl(internal_ip.s_addr)) {
		//outbound
		consoleLog("Outbound UDP");
		// search NAT table
		int i, found = -1, externalPort=0;

		for (i = 0; i < PORT_SIZE; i++) {
			if (table[i].valid == 0)
				continue;
			if (table[i].protocol == IPPROTO_UDP && ts - table[i].ts > 30) {
				//scan and invalidate those timeout udp ports
				closePort(sockets[table[i].external_port - PORT_OFFSET]);
				table[i].valid = 0;
				consoleLog("UDP Timeout");
			} else if (table[i].protocol == IPPROTO_UDP
					&& (table[i].internal_address == sAddr)
					&& (table[i].internal_port == sPort)) {
				table[i].ts = ts;
				externalPort = table[i].external_port;
				found = i;
				printf("line723: %d\n", i);
			}
		}
		printf("line727: UDP Found : %d, externalPort: %d\n", found, externalPort);
		if (found == -1) {
			consoleLog("line728: UPD not found");
			externalPort = getSmallestAvailablePort();
			i = externalPort - PORT_OFFSET;
			printf("line733: %d\n", i);
			table[i].internal_address = ntohl(iph->saddr);
			table[i].internal_port = ntohs(udph->source);
			table[i].ts = ts;
			table[i].protocol = IPPROTO_UDP;
			table[i].external_port = externalPort;
			table[i].tcp_states = 0;
			table[i].valid = 1;
		}

		consoleLog("UDP Translation");
		printf("line741: %d \n", externalPort);
		iph->saddr = public_ip.s_addr;
		// and the source port number with the translated port number
		consoleLog("line746 reached");
		udph->source = htons(externalPort);
		// NEED to modify fields of the IP and UDP headers
		//consoleLog("line748 reached");
		iph->check = ip_checksum((unsigned char*) iph);
		udph->check = udp_checksum((unsigned char*) iph);

		//FIXME len and pkt
		consoleLog("line752 reached");
		return nfq_set_verdict(qh, id, NF_ACCEPT, payloadLen,
				(unsigned char*) payload);
	} else {
		//inbound
		consoleLog("UDP Inbound");
		int i, found = -1;
		u_int16_t dest = ntohs(udph->dest);
		for (i = 0; i < PORT_SIZE; i++) {
			if (table[i].valid == 0)
				continue;
			if (table[i].protocol == IPPROTO_UDP && ts - table[i].ts > 30) {
				//scan and invalidate those timeout udp ports
				closePort(sockets[table[i].external_port - PORT_OFFSET]);
				table[i].valid = 0;
			} else if (table[i].protocol == IPPROTO_UDP
					&& table[i].external_port == dest) {
				table[i].ts = ts;
				found = i;
			}
		}

		if (found == -1) {
			consoleLog("UDP Inbound DROP");
			//2.2.c If not, the NAT program should drop the packet.
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} else {
			//2.2.b If yes, the NAT program modifies the destination IP address and the destination
			//port number of the inbound packet, and sends it to the target VM.
			iph->daddr = htonl(table[found].internal_address);
			udph->dest = htons(table[found].internal_port);

			iph->check = ip_checksum((unsigned char*) iph);
			udph->check = udp_checksum((unsigned char*) iph);
			consoleLog("UDP Inbound ACCEPT");
			return nfq_set_verdict(qh, id, NF_ACCEPT, payloadLen, payload);
		}

	}
}

/**
 * ./nat <public ip> <internal ip> <subnet mask>
 */
int main(int argc, char** argv) {

	if (argc <= 3) {
		printf("$ ./nat <public ip> <internal ip> <subnet mask>\n");
		return -1;
	}

	if (inet_aton(argv[1], &public_ip) == 0) {
		printf("$ ./nat <public ip> <internal ip> <subnet mask>\n");
		return -1;
	}
	if (inet_aton(argv[2], &internal_ip) == 0) {
		printf("$ ./nat <public ip> <internal ip> <subnet mask>\n");
		return -1;
	}
	unsigned int netmask = (unsigned int) atoi(argv[3]);
	subnet_mask = 0xFFFFFFFF << (32 - netmask);

	//printf("public ip: %s , internal ip:%s, subnet mask: %s\n", argv[1], argv[2], argv[3]);
	printf("success run");

	int res;
	char buf[4096];
	struct handles handles;
	//Boostrap phase
	bootstrap(&handles);

	//Main phase
	//process matched packed
	while ((res = recv(handles.fd, buf, sizeof(buf), 0)) && res >= 0) {
		nfq_handle_packet(handles.h, buf, res);
	}

	//End phase
	nfq_destroy_queue(handles.qh);
	nfq_close(handles.h);
	return 0;
}
