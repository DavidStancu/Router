#include "protocols.h"
#include "queue.h"
#include "list.h"
#include "lib.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// initially when i made the arp table i allocated its size to 6 but i removed
// it after i turned it into a linked list
#define R_TABLE_SIZE 100000

#define IPV4 0x0800 // IPV4 protocol type shortcut
#define ARP 0x0806 // ARP protocol type shortcut

// below is the strcture of a packet used for the arp request
typedef struct p_packet {
	char *packet;
	size_t len;
	int interface;
	uint32_t next_hop;
} p_packet;

// pointer to the routing table
struct route_table_entry *rtable;
// size of the routing table
int rtable_size;

// created the arp table as a linked list
list_node *arp_table;

// queue for pending packets awating ARP processing 
queue packets;

// function that searches for the best route for the given ip address
struct route_table_entry *get_best_route(uint32_t ip) {
	struct route_table_entry *best_route = NULL;
	for (int i = 0; i < rtable_size; i++) {
		if ((ip & rtable[i].mask) == rtable[i].prefix) {
			// if the route uses a speciffic mask, the best route is updated
			if (!best_route || best_route->mask <= rtable[i].mask)
				best_route = &rtable[i];
		}
	}
	return best_route;
}

// function that retrieves the next hop's MAC address using the ARP table
struct arp_table_entry *get_dest_mac(uint32_t next_hop) {
	list_node *current = arp_table;
	while (current != NULL) {
		struct arp_table_entry *entry = (struct arp_table_entry *)current->data;
		if (entry->ip == next_hop)
			return entry;
		else
			current = current->next;
	}
	// if no hop found, then i retuen NULL
	return NULL;
}

// function used to add a new ARP table or updates it if it already existed
void add_arp_entry(uint32_t ip, uint8_t *mac) {
	struct arp_table_entry *existing_entry = get_dest_mac(ip);
	if (existing_entry) {
		memcpy(existing_entry->mac, mac, 6);
		return;
	}

	struct arp_table_entry *new_entry = malloc(sizeof(struct arp_table_entry));
	new_entry->ip = ip;
	memcpy(new_entry->mac, mac, 6);
	insert_node(&arp_table, new_entry, list_len(arp_table));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// i'm initialising the route table and allocating memory for it
	rtable = malloc(R_TABLE_SIZE * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);

	// initialising the ARP table and the pending packet queue
	arp_table = new_list();
	packets = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// i'm creating a copy of the original buffer so i can use it later
		char orig_buf[MAX_PACKET_LEN];
		memcpy(orig_buf, buf, len);

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		// i'm getting the MAC address 
		uint8_t router_mac[6];
		get_interface_mac(interface, router_mac);

		// if the packets are NOT addressed to the current router, they are skipped
		if (memcmp(eth_hdr->ethr_dhost, router_mac, 6) != 0 &&
			memcmp(eth_hdr->ethr_dhost, (uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 6) != 0){
			continue;
		}

		// getting the ethernet type
		uint16_t ether_type = ntohs(eth_hdr->ethr_type);
		
		if (ether_type == IPV4) { // type is IPV4
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			// storing checksum so i can compare it easier
			int old_checksum = ip_hdr->checksum;
			ip_hdr->checksum = 0;
			if(old_checksum != htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)))){
				continue; // if the checksum is not valid, it is skipped
			}

			if (ip_hdr->proto == 1) { // handles ICMP requests
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				uint32_t my_ip = inet_addr(get_interface_ip(interface));
				if (ip_hdr->dest_addr == my_ip && icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
					// setting up the ICMP reply
					icmp_hdr->mtype = 0;
					icmp_hdr->mcode = 0;
					icmp_hdr->check = 0;
					int icmp_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);
					icmp_hdr->check = htons(checksum((uint16_t*)icmp_hdr, icmp_len));
					
					// swap the address and destination
					uint32_t aux = ip_hdr->source_addr;
					ip_hdr->source_addr = ip_hdr->dest_addr;
					ip_hdr->dest_addr = aux;

					// calculateing checksum again
					ip_hdr->checksum = 0;
					ip_hdr->checksum = htons(checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr)));
					
					//swap the MAC addresses as well
					uint8_t aux_mac[6];
					memcpy(aux_mac, eth_hdr->ethr_shost, 6);
					memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
					memcpy(eth_hdr->ethr_dhost, aux_mac, 6);
					
					// sends reply
					send_to_link(len, buf, interface);
					continue;
				}
			}

			if (ip_hdr->ttl <= 1) { // TTL expired => ICMP timeout
				// creates a packet for the message
				char packet[MAX_PACKET_LEN];
				memset(packet, 0, MAX_PACKET_LEN);

				// gets ethernet header info
				struct ether_hdr *eth_reply = (struct ether_hdr *) packet;
				memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
				get_interface_mac(interface, eth_reply->ethr_shost);
				eth_reply->ethr_type = htons(IPV4);

				// putting in IP header info
				struct ip_hdr *ip_reply = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
				ip_reply->ver = 4;
				ip_reply->ihl = 5;
				ip_reply->tos = 0;
				
				// calculating the correct size
				int temp_size;
				if (ip_hdr->ihl * 4 + 8 > (int)(len - sizeof(struct ether_hdr)))
					temp_size = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + (len - sizeof(struct ether_hdr));
				else
					temp_size = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + (ip_hdr->ihl * 4 + 8);
				ip_reply->tot_len = htons(temp_size);
				
				ip_reply->id = 0;
				ip_reply->frag = 0;
				ip_reply->ttl = 64;
				ip_reply->proto = 1; // protocol set ti ICMP
				ip_reply->source_addr = inet_addr(get_interface_ip(interface));
				ip_reply->dest_addr = ip_hdr->source_addr;
				ip_reply->checksum = 0;
				ip_reply->checksum = htons(checksum((uint16_t *)ip_reply, ip_reply->ihl * 4));

				//putting in ICMP header info
				struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + ip_reply->ihl * 4);
				icmp_reply->mtype = 11; // code for ICMP timeout
				icmp_reply->mcode = 0;
				icmp_reply->check = 0;

				// i copy part of the OG packet into the payload
				char *icmp_data = (char *)(packet + sizeof(struct ether_hdr) + ip_reply->ihl * 4 + sizeof(struct icmp_hdr));
				size_t copy_len;
				if ((len - sizeof(struct ether_hdr)) < (ip_hdr->ihl * 4 + 8)) 
					copy_len = len - sizeof(struct ether_hdr); //if there is less info than desired 
				else
					copy_len = ip_hdr->ihl * 4 + 8; // if not, i copy 8 bytes of the original payload
				
				// copies the data into the payload
				memcpy(icmp_data, orig_buf + sizeof(struct ether_hdr), copy_len);
				icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, sizeof(struct icmp_hdr) + copy_len));

				// get the packet length and send the packet
				size_t packet_len = sizeof(struct ether_hdr) + ntohs(ip_reply->tot_len);
				send_to_link(packet_len, packet, interface);
				continue;
			}

			ip_hdr->ttl--; // decrease ttl due to hopping
			ip_hdr->checksum = 0; // prepares and recalculates checksum
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			// getting best route
			struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);

			if (!best_route){ // route has not been reached => ICMP host unreached 
			// most steps here are the same for previous
				char packet[MAX_PACKET_LEN];
				memset(packet, 0, MAX_PACKET_LEN);

				struct ether_hdr *eth_reply = (struct ether_hdr *) packet;
				memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
				get_interface_mac(interface, eth_reply->ethr_shost);

				// preparing the IP header for the reply
				struct ip_hdr *ip_new = (struct ip_hdr *) (packet + sizeof(struct ether_hdr));
				ip_new->ver = 4;
				ip_new->ihl = 5;
				ip_new->tos = 0;
				uint16_t total_len = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + (ip_hdr->ihl * 4 + 8);
				ip_new->tot_len = htons(total_len);
				ip_new->id = htons(4);
				ip_new->frag = 0;
				ip_new->ttl = 64;
				ip_new->proto = 1;
				ip_new->source_addr = inet_addr(get_interface_ip(interface));
				ip_new->dest_addr = ((struct ip_hdr *)(orig_buf + sizeof(struct ether_hdr)))->source_addr;
				ip_new->checksum = 0;
				ip_new->checksum = htons(checksum((uint16_t *)ip_new, ip_new->ihl * 4));

				struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + ip_new->ihl * 4);
				icmp_reply->mtype = 3; // ICMP code for host unreachable
				icmp_reply->mcode = 0;
				icmp_reply->check = 0;

				// copies the data for the payload, just like for the previous error
				char *icmp_data = (char *) icmp_reply + 8;
				size_t copy_len = (ip_hdr->ihl * 4 + 8);
				if ((len - sizeof(struct ether_hdr)) < copy_len)
					copy_len = len - sizeof(struct ether_hdr);

				memcpy(icmp_data, orig_buf + sizeof(struct ether_hdr), copy_len);
				icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, 8 + copy_len));

				//getting best route
				struct route_table_entry *rt_entry = get_best_route(((struct ip_hdr *)(orig_buf + sizeof(struct ether_hdr)))->source_addr);
				int out_interface = rt_entry->interface;
				uint32_t next_hop;
				//finding the next hop if available
				if (rt_entry->next_hop != 0)
					next_hop = rt_entry->next_hop;
				else
					next_hop = ((struct ip_hdr *)(orig_buf + sizeof(struct ether_hdr)))->source_addr;
					
				struct arp_table_entry *arp_entry = get_dest_mac(next_hop);

				// getting the MAC address
				get_interface_mac(out_interface, eth_reply->ethr_shost);
				memcpy(eth_reply->ethr_dhost, arp_entry->mac, 6);
				eth_reply->ethr_type = htons(IPV4);
				// calculating total langth and sending the reply
				size_t packet_len = sizeof(struct ether_hdr) + total_len;
				send_to_link(packet_len, packet, out_interface);
				continue;
			}

			// checks for entry in the ARP table
			struct arp_table_entry *dest_mac = get_dest_mac(best_route->next_hop);
			if (!dest_mac){ // not reached => prepares the reply packet
				//fills in the pending packet info
				p_packet *pending = malloc(sizeof(p_packet));
				pending->packet = malloc(len);
				memcpy(pending->packet, buf, len);
				pending->len = len;
				pending->interface = best_route->interface;
				pending->next_hop = best_route->next_hop;
				queue_enq(packets, pending);

				// creates ARP request packet
				char packet[MAX_PACKET_LEN];
				memset(packet, 0, MAX_PACKET_LEN);

				// gets the source MAC info
				struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;
				get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
				memset(eth_hdr->ethr_dhost, 0xff, 6);
				eth_hdr->ethr_type = htons(ARP);
				
				// fills in the ARP header info
				struct arp_hdr *arp_hdr = (struct arp_hdr *)(packet + sizeof(struct ether_hdr));
				arp_hdr->hw_type = htons(1);
				arp_hdr->proto_type = htons(IPV4);
				arp_hdr->hw_len = 6;
				arp_hdr->proto_len = 4;
				arp_hdr->opcode = htons(1);

				//gets the MAC source
				get_interface_mac(best_route->interface, arp_hdr->shwa);
				arp_hdr->sprotoa = inet_addr(get_interface_ip(best_route->interface));
				memset(arp_hdr->thwa, 0, 6);
				arp_hdr->tprotoa = best_route->next_hop;

				//sengding the packet
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), packet, best_route->interface);
				continue;
			}

			// since the MAC address is known we set the ethernet header and set the packet
			memcpy(eth_hdr->ethr_dhost, dest_mac->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			send_to_link(len, buf, best_route->interface);
		} else if (ether_type == ARP) { // type is ARP
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			if (ntohs(arp_hdr->opcode) == 1) {
				uint32_t ip = inet_addr(get_interface_ip(interface));
				if (arp_hdr->tprotoa == ip) { // if ARP request matches
					// building the ARP response
					memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
					get_interface_mac(interface, eth_hdr->ethr_shost);

					arp_hdr->opcode = htons(2);
					// swaps ARP addresses
					uint32_t aux_ip = arp_hdr->sprotoa;
					arp_hdr->sprotoa = ip;
					arp_hdr->tprotoa = aux_ip;

					//swaps MAC addresses
					uint8_t aux_mac[6];
					memcpy(aux_mac, arp_hdr->shwa, 6);
					memcpy(arp_hdr->shwa, eth_hdr->ethr_shost, 6);
					memcpy(arp_hdr->thwa, aux_mac, 6);

					// sending ARP reply
					send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
				}
			} else if (ntohs(arp_hdr->opcode) == 2) { // if ARP is reply
				// adds new ARP entry
				add_arp_entry(arp_hdr->sprotoa, arp_hdr->shwa);
				int q_size = queue_len(packets);
				for (int i = 0; i < q_size; i++) {
					p_packet *pending = (p_packet *) queue_deq(packets);
					if (pending->next_hop == arp_hdr->sprotoa) {
						// i start building the ethernet packet 
						struct ether_hdr *eth_hdr = (struct ether_hdr *) pending->packet;
						get_interface_mac(pending->interface, eth_hdr->ethr_shost);
						memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
						// sending the packet
						send_to_link(pending->len, pending->packet, pending->interface);
						// freeing the memory
						free(pending->packet);
						free(pending);
					} else { //if not for this hop, put it back in the queue
						queue_enq(packets, pending);
					}
				}
			}
		}
	}
}