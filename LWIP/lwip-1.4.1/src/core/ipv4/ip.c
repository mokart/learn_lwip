/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 * 
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"
#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp_impl.h"
#include "lwip/snmp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "arch/perf.h"

#include <string.h>

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */
#ifndef LWIP_INLINE_IP_CHKSUM
#define LWIP_INLINE_IP_CHKSUM   1
#endif
#if LWIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP_INLINE  1
#else
#define CHECKSUM_GEN_IP_INLINE  0
#endif

#if LWIP_DHCP || defined(LWIP_IP_ACCEPT_UDP_PORT)
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 1

/** Some defines for DHCP to let link-layer-addressed packets through while the
 * netif is down.
 * To use this in your own application/protocol, define LWIP_IP_ACCEPT_UDP_PORT
 * to return 1 if the port is accepted and 0 if the port is not accepted.
 */
#if LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT)
/* accept DHCP client port and custom port */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (((port) == PP_NTOHS(DHCP_CLIENT_PORT)) \
         || (LWIP_IP_ACCEPT_UDP_PORT(port)))
#elif defined(LWIP_IP_ACCEPT_UDP_PORT) /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept custom port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (LWIP_IP_ACCEPT_UDP_PORT(port))
#else /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept DHCP client port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) ((port) == PP_NTOHS(DHCP_CLIENT_PORT))
#endif /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */

#else /* LWIP_DHCP */
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 0
#endif /* LWIP_DHCP */

/**
 * The interface that provided the packet for the current callback
 * invocation.
 */
 //��������ȫ�ֱ����������������ļ��б�����
struct netif *current_netif;          //ָ����յ���ǰ��������ݱ�������ӿڽṹ

/**
 * Header of the input packet currently being processed.
 */
const struct ip_hdr *current_header;  //ָ��ǰ��������ݱ����ײ�

/** Source IP address of current_header */
ip_addr_t current_iphdr_src;
/** Destination IP address of current_header */
ip_addr_t current_iphdr_dest;

/** The IP header ID of the next outgoing IP packet */
static u16_t ip_id;

/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
 //�������� : ����Ŀ��IP��ַѡ��һ������ʵ�����ӿڽṹ
 //����     : Ŀ��IP��ַ
 //����ֵ   : ָ����Ӧ����ӿڽṹ��ָ��
struct netif *
ip_route(ip_addr_t *dest)
{
  struct netif *netif;

#ifdef LWIP_HOOK_IP4_ROUTE
  netif = LWIP_HOOK_IP4_ROUTE(dest);
  if (netif != NULL) {
    return netif;
  }
#endif

  /* iterate through netifs */
  for (netif = netif_list; netif != NULL; netif = netif->next)          //���α����ӿڽṹ����
  {
    /* network mask matches? */
    if (netif_is_up(netif))        //�ӿ��Ѿ�ʹ��
	{
      if (ip_addr_netcmp(dest, &(netif->ip_addr), &(netif->netmask)))   //����Ŀ��IP��ַ��������ͬһ�����ڣ��򷵻�����ӿڽṹ
	  {
        /* return netif on which to forward IP packet */
        return netif;
      }
    }
  } //for
  //�����˵��û���ҵ����ʵĽӿڣ����ǰ�ϵ�е�Ĭ������ӿ���Ϊ�������
  if ((netif_default == NULL) || (!netif_is_up(netif_default))) //���Ĭ������ӿ�δ���û�δʹ�ܣ��򷵻ؿ�ָ��
  {
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    snmp_inc_ipoutnoroutes();
    return NULL;                            //δʹ�ܣ��򷵻ؿ�ָ��
  }
  /* no matching netif found, use default netif */
  return netif_default;                     //����Ĭ������ӿ�
}

#if IP_FORWARD
/**
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 * @param p the packet to forward
 * @param dest the destination IP address
 * @return 1: can forward 0: discard
 */
static int
ip_canforward(struct pbuf *p)
{
  u32_t addr = ip4_addr_get_u32(ip_current_dest_addr());

  if (p->flags & PBUF_FLAG_LLBCAST) {
    /* don't route link-layer broadcasts */
    return 0;
  }
  if ((p->flags & PBUF_FLAG_LLMCAST) && !IP_MULTICAST(addr)) {
    /* don't route link-layer multicasts unless the destination address is an IP
       multicast address */
    return 0;
  }
  if (IP_EXPERIMENTAL(addr)) {
    return 0;
  }
  if (IP_CLASSA(addr)) {
    u32_t net = addr & IP_CLASSA_NET;
    if ((net == 0) || (net == (IP_LOOPBACKNET << IP_CLASSA_NSHIFT))) {
      /* don't route loopback packets */
      return 0;
    }
  }
  return 1;
}

/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
 //������ӿ��µ�����ת��
static void
ip_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct netif *netif;

  PERF_START;

  if (!ip_canforward(p)) {
    goto return_noroute;
  }

  /* RFC3927 2.7: do not forward link-local addresses */
  if (ip_addr_islinklocal(&current_iphdr_dest)) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_forward: not forwarding LLA %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(&current_iphdr_dest), ip4_addr2_16(&current_iphdr_dest),
      ip4_addr3_16(&current_iphdr_dest), ip4_addr4_16(&current_iphdr_dest)));
    goto return_noroute;
  }

  /* Find network interface where to forward this IP packet to. */
  netif = ip_route(&current_iphdr_dest);
  if (netif == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_forward: no forwarding route for %"U16_F".%"U16_F".%"U16_F".%"U16_F" found\n",
      ip4_addr1_16(&current_iphdr_dest), ip4_addr2_16(&current_iphdr_dest),
      ip4_addr3_16(&current_iphdr_dest), ip4_addr4_16(&current_iphdr_dest)));
    /* @todo: send ICMP_DUR_NET? */
    goto return_noroute;
  }
#if !IP_FORWARD_ALLOW_TX_ON_RX_NETIF
  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_forward: not bouncing packets back on incoming interface.\n"));
    goto return_noroute;
  }
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);          //ת��ǰ���Ƚ�IP���ݱ��ײ��е�TTL�ֶ�ֵ��һ
  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {                       //��TTL��Ϊ0
    snmp_inc_ipinhdrerrors();
#if LWIP_ICMP
    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) 
	{
      icmp_time_exceeded(p, ICMP_TE_TTL);         //��Դ��������һ��ICMP��ʱ��Ϣ����ʾ��ǰ���ݵ��������ڵ��ˣ�������ݱ������ﱻ����������ת��
    }
#endif /* LWIP_ICMP */
    return;
  }

  /* Incrementally update the IP checksum. */
  if (IPH_CHKSUM(iphdr) >= PP_HTONS(0xffffU - 0x100)) {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + PP_HTONS(0x100) + 1);
  } else {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + PP_HTONS(0x100));
  }

  LWIP_DEBUGF(IP_DEBUG, ("ip_forward: forwarding packet to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
    ip4_addr1_16(&current_iphdr_dest), ip4_addr2_16(&current_iphdr_dest),
    ip4_addr3_16(&current_iphdr_dest), ip4_addr4_16(&current_iphdr_dest)));

  IP_STATS_INC(ip.fw);
  IP_STATS_INC(ip.xmit);
  snmp_inc_ipforwdatagrams();

  PERF_STOP("ip_forward");
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu)) 
  {
    if ((IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF)) == 0) 
	{
#if IP_FRAG
      ip_frag(p, netif, ip_current_dest_addr());
#else /* IP_FRAG */
      /* @todo: send ICMP Destination Unreacheable code 13 "Communication administratively prohibited"? */
#endif /* IP_FRAG */
    } 
	else 
	{
      /* send ICMP Destination Unreacheable code 4: "Fragmentation Needed and DF Set" */
      icmp_dest_unreach(p, ICMP_DUR_FRAG);
    }
    return;
  }
  
  /* transmit pbuf on chosen interface */
  netif->output(netif, p, &current_iphdr_dest);
  return;
return_noroute:
  snmp_inc_ipoutnoroutes();
}
#endif /* IP_FORWARD */

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 * 
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
 //�������� : �����յ���IP���ݱ�
 //����p    : ָ����յ������ݱ� pbuf
 //����inp  : ָ���յ������ݱ�������ӿ�
err_t
ip_input(struct pbuf *p, struct netif *inp)
{
  struct ip_hdr *iphdr;                      //���ݱ��ײ�ָ��
  struct netif *netif;                       //����ӿڽṹָ��
  u16_t iphdr_hlen;                          //���ݱ��ײ�����
  u16_t iphdr_len;                           //���ݱ��ܳ���
  
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  int check_ip_src=1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  IP_STATS_INC(ip.recv);
  snmp_inc_ipinreceives();

  /* identify the IP header */
  iphdr = (struct ip_hdr *)p->payload;          //iphdrָ��pbuf�е����ݱ��ײ�
  if (IPH_V(iphdr) != 4) {                      //�жϰ汾���Ƿ���4��ֻ����IPV4�����ݱ�
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", IPH_V(iphdr)));
    ip_debug_print(p);              
    pbuf_free(p);                               //�汾�Ų�����Ҫ����ֱ��ɾ�����ݱ�
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    snmp_inc_ipinhdrerrors();
    return ERR_OK;                              //���ش���������������
  }

#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* obtain IP header length in number of 32-bit words */
  iphdr_hlen = IPH_HL(iphdr);                   //��ȡ�ײ������ֶΣ���4�ֽ�Ϊ��λ
  /* calculate IP header length in bytes */
  iphdr_hlen *= 4;                              //�����ײ����ȣ����ֽ�Ϊ��λ
  /* obtain ip length in bytes */
  iphdr_len = ntohs(IPH_LEN(iphdr));            //��ȡ���ݱ��ܳ����ֶΣ�ת��Ϊ������

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  //������鳤���ֶΣ������ݱ��ܳ��ȴ���pbuf���е��������ݳ��ȣ�����
  //���ݱ��ײ����ȴ��ڵ�һ��pbuf�е����ݳ���ʱ���������ݱ�
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len)) 
  {
    if (iphdr_hlen > p->len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
        iphdr_hlen, p->len));
    }
    if (iphdr_len > p->tot_len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
        iphdr_len, p->tot_len));
    }
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    snmp_inc_ipindiscards();
    return ERR_OK;                     //���ش���������������
  }

  /* verify checksum */
#if CHECKSUM_CHECK_IP
  //�������У��ͣ�����10.2���������������ݱ���У���Ӧ��Ϊ0
  if (inet_chksum(iphdr, iphdr_hlen) != 0) {  //������������

    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
      ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
    ip_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.chkerr);
    IP_STATS_INC(ip.drop);
    snmp_inc_ipinhdrerrors();
    return ERR_OK;                 //���ش���������������
  }
#endif

  /* Trim pbuf. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
  pbuf_realloc(p, iphdr_len);   //����pbuf�ĳ��ȣ�ɾ����̫��֡β��������ֶ�(����)
  //���������鿴Ŀ��IP��ַ�Ƿ��뱾��IP��ַƥ�䣬������Ҫ��������netif_list
  //�Ա���������ӿڽṹ��IP��ַ
  
  /* copy IP addresses to aligned ip_addr_t */
  ip_addr_copy(current_iphdr_dest, iphdr->dest);
  ip_addr_copy(current_iphdr_src, iphdr->src);

  /* match packet against an interface, i.e. is this packet for us? */
#if LWIP_IGMP
  if (ip_addr_ismulticast(&current_iphdr_dest)) 
  {
    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, &current_iphdr_dest))) {
      netif = inp;
    } else {
      netif = NULL;
    }
  } else
#endif /* LWIP_IGMP */
  {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs.
       'first' is used as a boolean to mark whether we started walking the list */
    int first = 1;             //�ֲ���������־�Ƿ��ѿ�ʼ��������netif_list
    netif = inp;               //�����ж��ǲ��ǽ��ܵ����ݰ�������ӿڣ���Ϊ����������
    do {
      LWIP_DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
          ip4_addr_get_u32(&iphdr->dest), ip4_addr_get_u32(&netif->ip_addr),
          ip4_addr_get_u32(&iphdr->dest) & ip4_addr_get_u32(&netif->netmask),
          ip4_addr_get_u32(&netif->ip_addr) & ip4_addr_get_u32(&netif->netmask),
          ip4_addr_get_u32(&iphdr->dest) & ~ip4_addr_get_u32(&netif->netmask)));

      /* interface is up and configured? */
      if ((netif_is_up(netif)) && (!ip_addr_isany(&(netif->ip_addr)))) 
	  {
	    //�������IP��ַ��Ȼ���Ŀ��IP��ַΪ�ýӿ��ϵĹ㲥��ַ
        /* unicast to this interface address? */
        if (ip_addr_cmp(&current_iphdr_dest, &(netif->ip_addr)) ||
            /* or broadcast on this interface network address? */
            ip_addr_isbroadcast(&current_iphdr_dest, netif)) {
          LWIP_DEBUGF(IP_DEBUG, ("ip_input: packet accepted on interface %c%c\n",
              netif->name[0], netif->name[1]));
          /* break out of for loop */
          break;                       //�˳�ѭ����netif �б����˲��ҽ��
        }
#if LWIP_AUTOIP
        /* connections to link-local addresses must persist after changing
           the netif's address (RFC3927 ch. 1.9) */
        if ((netif->autoip != NULL) &&
            ip_addr_cmp(&current_iphdr_dest, &(netif->autoip->llipaddr))) {
          LWIP_DEBUGF(IP_DEBUG, ("ip_input: LLA packet accepted on interface %c%c\n",
              netif->name[0], netif->name[1]));
          /* break out of for loop */
          break;
        }
#endif /* LWIP_AUTOIP */
      }

	  if (first) {                    //����ʧ�ܣ���firstΪ1����ʼ��������netif_list
        first = 0;                    //���ÿ�ʼ��־
        netif = netif_list;           //�õ���һ���ӿڽṹ
      } 
	  else                            //��������ѿ�ʼ
	  {
        netif = netif->next;          //�õ���һ���ӿڽṹ
      }
	  
      if (netif == inp) {             //����ӿڽṹ���ǽ��յ����ݱ����Ǹ��������ѽ���
        netif = netif->next;          //�ʼ�жϹ��ˣ��������õ���һ���ӿڽṹ
      }
    } while(netif != NULL);  //�ӿڽṹ��Ч����ѭ��
  }

#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == PP_NTOHS(12345))
   */
  if (netif == NULL) 
  {
    /* remote port is DHCP server? */
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)iphdr + iphdr_hlen);
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip_input: UDP packet to DHCP client port %"U16_F"\n",
        ntohs(udphdr->dest)));
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip_input: DHCP packet accepted.\n"));
        netif = inp;
        check_ip_src = 0;
      }
    }
  }
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
  if (check_ip_src && !ip_addr_isany(&current_iphdr_src))
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
  {  //�����������ݣ�ֱ�Ӷ���
     
     if ((ip_addr_isbroadcast(&current_iphdr_src, inp)) ||
         (ip_addr_ismulticast(&current_iphdr_src))) 
     {
      /* packet source is not valid */
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("ip_input: packet source is not valid.\n"));
      /* free (drop) packet pbufs */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      snmp_inc_ipinaddrerrors();
      snmp_inc_ipindiscards();
      return ERR_OK;
    }
  }

  /* packet not for us? */
  //��������û���ҵ���Ӧ������ӿڣ� ˵�����ݱ����ϸ����صģ����Խ����ݱ�ת����ȥ
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip_input: packet not for us.\n"));
#if IP_FORWARD
    /* non-broadcast packet? */
    if (!ip_addr_isbroadcast(&current_iphdr_dest, inp))     //��ת���㲥���ݱ�
	{ 
      /* try to forward IP packet on (other) interfaces */
      ip_forward(p, iphdr, inp);                            //����ip_forward�������ӿ���ת�����ݱ�
    } 
	else
#endif /* IP_FORWARD */
    {
      snmp_inc_ipinaddrerrors();
      snmp_inc_ipindiscards();
    }
    pbuf_free(p);
    return ERR_OK;
  }
  /* packet consists of multiple fragments */
  //���ݱ��Ǹ����صģ������ж��Ƿ�Ϊ��Ƭ���ݱ������ǣ�����з�Ƭ����
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) 
  {  
    //�����Ƭ��־��λ������Ƭƫ������Ϊ0
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip_reass()\n",
      ntohs(IPH_ID(iphdr)), p->tot_len, ntohs(IPH_LEN(iphdr)), !!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)*8));
    /* reassemble the packet*/
    p = ip_reass(p);                         //���ú���ip_reass��װ���ݱ�
    /* packet not fully reassembled yet? */
    if (p == NULL) {                         //�����Ƭ��װ��ɣ���ip_reass�����᷵��������װ�õ����ݱ������򷵻�NULL,�ҷ�Ƭ�ᱻ��ʱ������Э��ջ�ڲ�
      return ERR_OK;                         //δ��װ�ã�ip_input����ֱ�ӷ���
    }
	
    iphdr = (struct ip_hdr *)p->payload;     //��Ƭ��װ��ɣ���iphdrָ���������ݱ����ײ�
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since it was fragmented (0x%"X16_F") (while IP_REASSEMBLY == 0).\n",
      ntohs(IPH_OFFSET(iphdr))));
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    snmp_inc_ipinunknownprotos();
    return ERR_OK;
#endif /* IP_REASSEMBLY */
  }

#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else

  //����������Ƿ񾭹���Ƭ���飬���ǵõ���Ӧ����һ�����������ݱ�
  //�ж�IP�ײ�����
  if (iphdr_hlen > IP_HLEN) 
  { 
    //��������ײ�ѡ������ݱ�
#endif /* LWIP_IGMP */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    snmp_inc_ipinunknownprotos();
    return ERR_OK;
  }
#endif /* IP_OPTIONS_ALLOWED == 0 */

  /* send to upper layers */
  LWIP_DEBUGF(IP_DEBUG, ("ip_input: \n"));
  ip_debug_print(p);
  LWIP_DEBUGF(IP_DEBUG, ("ip_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  //���������У�鹤����ɣ������ݱ����ϲ�ݽ�
  current_netif = inp;                          //��¼�½��յ���ǰ���ݱ�������ӿڽṹ
  current_header = iphdr;                       //��ǰ��������ݱ��ײ�

#if LWIP_RAW
  /* raw input did not eat the packet? */
  if (raw_input(p, inp) == 0)                   //Ϊ�û�ֱ����IP���ݱ�����Ԥ���Ľӿ�
#endif /* LWIP_RAW */
  {
    switch (IPH_PROTO(iphdr)) {                 //�����ײ��е�Э�������ֶΣ��ݽ�����ͬ���ϲ�Э��
#if LWIP_UDP                                    //UDPЭ������
    case IP_PROTO_UDP:
#if LWIP_UDPLITE
    case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
      snmp_inc_ipindelivers();
      udp_input(p, inp);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP                                    //TCPЭ������
    case IP_PROTO_TCP:
      snmp_inc_ipindelivers();
      tcp_input(p, inp);
      break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
    case IP_PROTO_ICMP:                                      //ICMPЭ������
      snmp_inc_ipindelivers();
      icmp_input(p, inp);
      break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
    case IP_PROTO_IGMP:                                     //IGMPЭ������
      igmp_input(p, inp, &current_iphdr_dest);
      break;
#endif /* LWIP_IGMP */
    default:                                                //�Ҳ����ϲ�Э�飬��ΪԴ��������Ŀ�Ĳ��ɴ�ICMP����
#if LWIP_ICMP
      /* send ICMP destination protocol unreachable unless is was a broadcast */
      if (!ip_addr_isbroadcast(&current_iphdr_dest, inp) &&
          !ip_addr_ismulticast(&current_iphdr_dest)) {
        p->payload = iphdr;                                //�����ݰ�playloadָ��ָ��IP���ݱ��ײ�
        icmp_dest_unreach(p, ICMP_DUR_PROTO);              //����ICMP����
      }
#endif /* LWIP_ICMP */
      pbuf_free(p);                                        //ɾ�����ݰ�pbuf

      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", IPH_PROTO(iphdr)));

      IP_STATS_INC(ip.proterr);
      IP_STATS_INC(ip.drop);
      snmp_inc_ipinunknownprotos();
    }
  }

  current_netif = NULL;                                    //������ȫ�ֱ�����0
  current_header = NULL;
  ip_addr_set_any(&current_iphdr_src);
  ip_addr_set_any(&current_iphdr_dest);

  return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
 //�������� : ��дIP�ײ��еĸ����ֶ�ֵ(������ѡ���ֶ�)�����������ݱ�
 //����˵�� : netifΪ�������ݰ�������ӿڽṹ������������ip_output����ͬ
err_t
ip_output_if(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
             u8_t ttl, u8_t tos,
             u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if() but with the possibility to include IP options:
 *
 * @ param ip_options pointer to the IP options, copied into the IP header
 * @ param optlen length of ip_options
 */
 //��ip_output_if ��� ��һ��ѡ���ֶ�
err_t ip_output_if_opt(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
       u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
  struct ip_hdr *iphdr;
  ip_addr_t dest_addr;
#if CHECKSUM_GEN_IP_INLINE
  u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
  LWIP_ASSERT("p->ref == 1", p->ref == 1);

  snmp_inc_ipoutrequests();

  /* Should the IP header be generated or is it already included in p */
  if (dest != IP_HDRINCL)
  {
    //dest ��ΪIP_HDRINCL,˵��pbuf��δ��дIP�ײ�
    u16_t ip_hlen = IP_HLEN;                     //��IP_HLENΪĬ�ϵ�IP�ײ����ȣ�20
#if IP_OPTIONS_SEND
    u16_t optlen_aligned = 0;
    if (optlen != 0) {
#if CHECKSUM_GEN_IP_INLINE
      int i;
#endif /* CHECKSUM_GEN_IP_INLINE */
      /* round up to a multiple of 4 */
      optlen_aligned = ((optlen + 3) & ~3);
      ip_hlen += optlen_aligned;
      /* First write in the IP options */
      if (pbuf_header(p, optlen_aligned)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output_if_opt: not enough room for IP options in pbuf\n"));
        IP_STATS_INC(ip.err);
        snmp_inc_ipoutdiscards();
        return ERR_BUF;
      }
      MEMCPY(p->payload, ip_options, optlen);
      if (optlen < optlen_aligned) {
        /* zero the remaining bytes */
        memset(((char*)p->payload) + optlen, 0, optlen_aligned - optlen);
      }
#if CHECKSUM_GEN_IP_INLINE
      for (i = 0; i < optlen_aligned/2; i++) {
        chk_sum += ((u16_t*)p->payload)[i];
      }
#endif /* CHECKSUM_GEN_IP_INLINE */
    }
#endif /* IP_OPTIONS_SEND */
    /* generate IP header */
    if (pbuf_header(p, IP_HLEN)) {               //�ƶ�payloadָ�룬ָ��pbuf�е�IP�ײ�
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output: not enough room for IP header in pbuf\n"));

      IP_STATS_INC(ip.err);
      snmp_inc_ipoutdiscards();
      return ERR_BUF;                            //ʧ��,����pbuf�ռ����
    }

    iphdr = (struct ip_hdr *)p->payload;         //iphdrָ�����ݱ��ײ�
    
    LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
               (p->len >= sizeof(struct ip_hdr)));

    IPH_TTL_SET(iphdr, ttl);                     //��дTTL�ֶ�
    IPH_PROTO_SET(iphdr, proto);                 //��дЭ���ֶ�
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += LWIP_MAKE_U16(proto, ttl);
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* dest cannot be NULL here */
    ip_addr_copy(iphdr->dest, *dest);            //��дĿ��IP��ַ
    
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);         //��д�汾��+�ײ�����+��������
    IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += LWIP_MAKE_U16(tos, iphdr->_v_hl);
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_LEN_SET(iphdr, htons(p->tot_len));      //��д���ݱ��ܳ���
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_OFFSET_SET(iphdr, 0);                   //��д��־λ��Ƭƫ���ֶΣ���Ϊ0
    IPH_ID_SET(iphdr, htons(ip_id));            //��д��ʶ�ֶ�
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
    ++ip_id;                                    //���ݱ����ֵ��1

    if (ip_addr_isany(src)) 
	{                                           //��srcΪ�գ���ԴIP��ַ��дΪ����ӿڵ�IP��ַ
      ip_addr_copy(iphdr->src, netif->ip_addr);
    } 
	else 
    {                                           //��src��Ϊ�գ���ֱ����дԴIP��ַ
      /* src cannot be NULL here */
      ip_addr_copy(iphdr->src, *src);
    }

#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
    chk_sum = (chk_sum >> 16) + chk_sum;
    chk_sum = ~chk_sum;
    iphdr->_chksum = chk_sum; /* network order */
#else /* CHECKSUM_GEN_IP_INLINE */
    IPH_CHKSUM_SET(iphdr, 0);                             //��0У����ֶ�
    
#if CHECKSUM_GEN_IP
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));   //���㲢��д�ײ�У���
#endif

#endif /* CHECKSUM_GEN_IP_INLINE */
  }
  else 
  {
    /* IP header already included in p */
    iphdr = (struct ip_hdr *)p->payload;
    ip_addr_copy(dest_addr, iphdr->dest);
    dest = &dest_addr;                     //ֻ���ñ���dest��¼�����ݱ��е�Ŀ��IP��ַ
  }
  
  IP_STATS_INC(ip.xmit);
  
  LWIP_DEBUGF(IP_DEBUG, ("ip_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], netif->num));
  ip_debug_print(p);
  
  //���濪ʼ����IP���ݱ������������������
#if ENABLE_LOOPBACK
  if (ip_addr_cmp(dest, &netif->ip_addr))              // ���Ŀ�� IP ��ַ�Ǳ������ĵ�ַ
  {
    /* Packet to self, enqueue it for loopback */
    LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
    return netif_loop_output(netif, p, dest);          //����û������룬�����������8��
  }
#if LWIP_IGMP
  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) 
  {
    netif_loop_output(netif, p, dest);
  }
#endif /* LWIP_IGMP */
#endif /* ENABLE_LOOPBACK */
#if IP_FRAG
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu))   //������ݱ�̫��(���ڽӿڵ�mtu)
  {
    return ip_frag(p, netif, dest);              //����ú���ip_frag�����ݱ���Ƭ����
  }
#endif /* IP_FRAG */
  
  LWIP_DEBUGF(IP_DEBUG, ("netif->output()"));
  //ʣ�µ������ֱ�ӵ��ýӿ�ע���output�����������ݱ�
  //netif->output=etharp_output;//IP�㷢�����ݰ�����������ʹ��ARP����غ���
  return netif->output(netif, p, dest);
}

/**
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
 //�������� : �������Э������Է������ݱ����ú�����������ӿڲ����ú���ip_output_if������յķ��͹���
 //���� p : �����Э����Ҫ���͵����ݰ�pbuf,payloadָ����ָ����Э���ײ�
 //���� src : ԴIP��ַ����ΪNULL����ʹ������ӿڽṹ�б����IP��ַ
 //���� dest : Ŀ��IP��ַ����ΪIP_HDRINCL,���ʾp���Ѿ�������õ�IP
 //�������ײ�����payloadָ��Ҳ�Ѿ�ָ����IP�ײ�
 //����ttl,tos,proto; IP�ײ��е�TTL�ֶΡ��������ͺ�Э������ֵ
err_t
ip_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
          u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
  LWIP_ASSERT("p->ref == 1", p->ref == 1);

  //����Ŀ��IP��ַΪ���ݱ�Ѱ��һ�����ʵ�����ӿ�
  if ((netif = ip_route(dest)) == NULL) { //���ҵ�������netifָ���Ӧ�Ľӿڽṹ
    LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;      //�Ҳ��������ؽӿڴ���
  }

  //��������netifΪ�������ú���if_output_if
  return ip_output_if(p, src, dest, ttl, tos, proto, netif);
}

#if LWIP_NETIF_HWADDRHINT
/** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param addr_hint address hint pointer set to netif->addr_hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip_output_hinted(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
          u8_t ttl, u8_t tos, u8_t proto, u8_t *addr_hint)
{
  struct netif *netif;
  err_t err;

  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
  LWIP_ASSERT("p->ref == 1", p->ref == 1);

  if ((netif = ip_route(dest)) == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  NETIF_SET_HWADDRHINT(netif, addr_hint);
  err = ip_output_if(p, src, dest, ttl, tos, proto, netif);
  NETIF_SET_HWADDRHINT(netif, NULL);

  return err;
}
#endif /* LWIP_NETIF_HWADDRHINT*/

#if IP_DEBUG
/* Print an IP header by using LWIP_DEBUGF
 * @param p an IP packet, p->payload pointing to the IP header
 */
void
ip_debug_print(struct pbuf *p)
{
  struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

  LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|%2"S16_F" |%2"S16_F" |  0x%02"X16_F" |     %5"U16_F"     | (v, hl, tos, len)\n",
                    IPH_V(iphdr),
                    IPH_HL(iphdr),
                    IPH_TOS(iphdr),
                    ntohs(IPH_LEN(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|    %5"U16_F"      |%"U16_F"%"U16_F"%"U16_F"|    %4"U16_F"   | (id, flags, offset)\n",
                    ntohs(IPH_ID(iphdr)),
                    ntohs(IPH_OFFSET(iphdr)) >> 15 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 14 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 13 & 1,
                    ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |    0x%04"X16_F"     | (ttl, proto, chksum)\n",
                    IPH_TTL(iphdr),
                    IPH_PROTO(iphdr),
                    ntohs(IPH_CHKSUM(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (src)\n",
                    ip4_addr1_16(&iphdr->src),
                    ip4_addr2_16(&iphdr->src),
                    ip4_addr3_16(&iphdr->src),
                    ip4_addr4_16(&iphdr->src)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (dest)\n",
                    ip4_addr1_16(&iphdr->dest),
                    ip4_addr2_16(&iphdr->dest),
                    ip4_addr3_16(&iphdr->dest),
                    ip4_addr4_16(&iphdr->dest)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* IP_DEBUG */
