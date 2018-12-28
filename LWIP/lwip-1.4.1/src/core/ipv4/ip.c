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
 //定义两个全局变量，可以在其他文件中被引用
struct netif *current_netif;          //指向接收到当前处理的数据报的网络接口结构

/**
 * Header of the input packet currently being processed.
 */
const struct ip_hdr *current_header;  //指向当前处理的数据报的首部

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
 //函数功能 : 根据目的IP地址选择一个最合适的网络接口结构
 //参数     : 目的IP地址
 //返回值   : 指向相应网络接口结构的指针
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
  for (netif = netif_list; netif != NULL; netif = netif->next)          //依次遍历接口结构链表
  {
    /* network mask matches? */
    if (netif_is_up(netif))        //接口已经使能
	{
      if (ip_addr_netcmp(dest, &(netif->ip_addr), &(netif->netmask)))   //且与目的IP地址主机处于同一子网内，则返回这个接口结构
	  {
        /* return netif on which to forward IP packet */
        return netif;
      }
    }
  } //for
  //到这里，说明没有找到合适的接口，我们把系列的默认网络接口作为结果返回
  if ((netif_default == NULL) || (!netif_is_up(netif_default))) //如果默认网络接口未配置或未使能，则返回空指针
  {
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    snmp_inc_ipoutnoroutes();
    return NULL;                            //未使能，则返回空指针
  }
  /* no matching netif found, use default netif */
  return netif_default;                     //返回默认网络接口
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
 //多网络接口下的数据转发
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
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);          //转发前，先将IP数据报首部中的TTL字段值减一
  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {                       //若TTL变为0
    snmp_inc_ipinhdrerrors();
#if LWIP_ICMP
    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) 
	{
      icmp_time_exceeded(p, ICMP_TE_TTL);         //向源主机发送一份ICMP超时信息，表示当前数据的生存周期到了，这个数据报在这里被丢弃，不再转发
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
 //函数功能 : 处理收到的IP数据报
 //参数p    : 指向接收到的数据报 pbuf
 //参数inp  : 指向收到的数据报的网络接口
err_t
ip_input(struct pbuf *p, struct netif *inp)
{
  struct ip_hdr *iphdr;                      //数据报首部指针
  struct netif *netif;                       //网络接口结构指针
  u16_t iphdr_hlen;                          //数据报首部长度
  u16_t iphdr_len;                           //数据报总长度
  
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  int check_ip_src=1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  IP_STATS_INC(ip.recv);
  snmp_inc_ipinreceives();

  /* identify the IP header */
  iphdr = (struct ip_hdr *)p->payload;          //iphdr指向pbuf中的数据报首部
  if (IPH_V(iphdr) != 4) {                      //判断版本号是否是4，只处理IPV4的数据报
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", IPH_V(iphdr)));
    ip_debug_print(p);              
    pbuf_free(p);                               //版本号不满足要求则直接删除数据报
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    snmp_inc_ipinhdrerrors();
    return ERR_OK;                              //返回处理结果，正常结束
  }

#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* obtain IP header length in number of 32-bit words */
  iphdr_hlen = IPH_HL(iphdr);                   //读取首部长度字段，以4字节为单位
  /* calculate IP header length in bytes */
  iphdr_hlen *= 4;                              //计算首部长度，以字节为单位
  /* obtain ip length in bytes */
  iphdr_len = ntohs(IPH_LEN(iphdr));            //读取数据报总长度字段，转换为主机序

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  //下面检验长度字段，当数据报总长度大于pbuf链中的所有数据长度，或者
  //数据报首部长度大于第一个pbuf中的数据长度时，丢弃数据报
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
    return ERR_OK;                     //返回处理结果，正常结束
  }

  /* verify checksum */
#if CHECKSUM_CHECK_IP
  //下面计算校验和，按照10.2节所述，接收数据报的校验和应该为0
  if (inet_chksum(iphdr, iphdr_hlen) != 0) {  //否则丢弃掉数据

    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
      ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
    ip_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.chkerr);
    IP_STATS_INC(ip.drop);
    snmp_inc_ipinhdrerrors();
    return ERR_OK;                 //返回处理结果，正常结束
  }
#endif

  /* Trim pbuf. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
  pbuf_realloc(p, iphdr_len);   //调整pbuf的长度，删除以太网帧尾部的填充字段(若有)
  //接下来，查看目的IP地址是否与本地IP地址匹配，这里需要查找链表netif_list
  //对比所有网络接口结构的IP地址
  
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
    int first = 1;             //局部变量，标志是否已开始遍历链表netif_list
    netif = inp;               //首先判断是不是接受到数据包的网络接口，因为这个概率最大
    do {
      LWIP_DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
          ip4_addr_get_u32(&iphdr->dest), ip4_addr_get_u32(&netif->ip_addr),
          ip4_addr_get_u32(&iphdr->dest) & ip4_addr_get_u32(&netif->netmask),
          ip4_addr_get_u32(&netif->ip_addr) & ip4_addr_get_u32(&netif->netmask),
          ip4_addr_get_u32(&iphdr->dest) & ~ip4_addr_get_u32(&netif->netmask)));

      /* interface is up and configured? */
      if ((netif_is_up(netif)) && (!ip_addr_isany(&(netif->ip_addr)))) 
	  {
	    //如果两个IP地址相等或者目的IP地址为该接口上的广播地址
        /* unicast to this interface address? */
        if (ip_addr_cmp(&current_iphdr_dest, &(netif->ip_addr)) ||
            /* or broadcast on this interface network address? */
            ip_addr_isbroadcast(&current_iphdr_dest, netif)) {
          LWIP_DEBUGF(IP_DEBUG, ("ip_input: packet accepted on interface %c%c\n",
              netif->name[0], netif->name[1]));
          /* break out of for loop */
          break;                       //退出循环，netif 中保存了查找结果
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

	  if (first) {                    //查找失败，且first为1，则开始查找链表netif_list
        first = 0;                    //设置开始标志
        netif = netif_list;           //得到第一个接口结构
      } 
	  else                            //链表查找已开始
	  {
        netif = netif->next;          //得到下一个接口结构
      }
	  
      if (netif == inp) {             //如果接口结构就是接收到数据报的那个，我们已将在
        netif = netif->next;          //最开始判断过了，跳过，得到下一个接口结构
      }
    } while(netif != NULL);  //接口结构有效，则循环
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
  {  //对于这类数据，直接丢弃
     
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
  //到这里，如果没有找到对应的网络接口， 说明数据报不上给本地的，可以将数据报转发出去
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip_input: packet not for us.\n"));
#if IP_FORWARD
    /* non-broadcast packet? */
    if (!ip_addr_isbroadcast(&current_iphdr_dest, inp))     //不转发广播数据报
	{ 
      /* try to forward IP packet on (other) interfaces */
      ip_forward(p, iphdr, inp);                            //调用ip_forward在其他接口上转发数据报
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
  //数据报是给本地的，下面判断是否为分片数据报，若是，则进行分片重组
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) 
  {  
    //更多分片标志置位，或者片偏移量不为0
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip_reass()\n",
      ntohs(IPH_ID(iphdr)), p->tot_len, ntohs(IPH_LEN(iphdr)), !!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)*8));
    /* reassemble the packet*/
    p = ip_reass(p);                         //调用函数ip_reass重装数据报
    /* packet not fully reassembled yet? */
    if (p == NULL) {                         //如果分片重装完成，则ip_reass函数会返回整个重装好的数据报，否则返回NULL,且分片会被暂时保存在协议栈内部
      return ERR_OK;                         //未重装好，ip_input函数直接返回
    }
	
    iphdr = (struct ip_hdr *)p->payload;     //分片重装完成，则iphdr指向整个数据报的首部
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

  //到这里，不管是否经过分片重组，我们得到的应该是一个完整的数据报
  //判断IP首部长度
  if (iphdr_hlen > IP_HLEN) 
  { 
    //不处理带首部选项的数据报
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

  //到这里，所有校验工作完成，将数据报向上层递交
  current_netif = inp;                          //记录下接收到当前数据报的网络接口结构
  current_header = iphdr;                       //当前处理的数据报首部

#if LWIP_RAW
  /* raw input did not eat the packet? */
  if (raw_input(p, inp) == 0)                   //为用户直接与IP数据报交互预留的接口
#endif /* LWIP_RAW */
  {
    switch (IPH_PROTO(iphdr)) {                 //根据首部中的协议类型字段，递交给不同的上层协议
#if LWIP_UDP                                    //UDP协议数据
    case IP_PROTO_UDP:
#if LWIP_UDPLITE
    case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
      snmp_inc_ipindelivers();
      udp_input(p, inp);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP                                    //TCP协议数据
    case IP_PROTO_TCP:
      snmp_inc_ipindelivers();
      tcp_input(p, inp);
      break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
    case IP_PROTO_ICMP:                                      //ICMP协议数据
      snmp_inc_ipindelivers();
      icmp_input(p, inp);
      break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
    case IP_PROTO_IGMP:                                     //IGMP协议数据
      igmp_input(p, inp, &current_iphdr_dest);
      break;
#endif /* LWIP_IGMP */
    default:                                                //找不到上层协议，则为源主机返回目的不可达ICMP报文
#if LWIP_ICMP
      /* send ICMP destination protocol unreachable unless is was a broadcast */
      if (!ip_addr_isbroadcast(&current_iphdr_dest, inp) &&
          !ip_addr_ismulticast(&current_iphdr_dest)) {
        p->payload = iphdr;                                //将数据包playload指针指向IP数据报首部
        icmp_dest_unreach(p, ICMP_DUR_PROTO);              //发送ICMP报文
      }
#endif /* LWIP_ICMP */
      pbuf_free(p);                                        //删除数据包pbuf

      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", IPH_PROTO(iphdr)));

      IP_STATS_INC(ip.proterr);
      IP_STATS_INC(ip.drop);
      snmp_inc_ipinunknownprotos();
    }
  }

  current_netif = NULL;                                    //将两个全局变量清0
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
 //函数功能 : 填写IP首部中的各个字段值(不处理选项字段)，并发送数据报
 //参数说明 : netif为发送数据包的网络接口结构，其他参数与ip_output的相同
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
 //跟ip_output_if 差不多 多一个选项字段
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
    //dest 不为IP_HDRINCL,说明pbuf中未填写IP首部
    u16_t ip_hlen = IP_HLEN;                     //宏IP_HLEN为默认的IP首部长度，20
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
    if (pbuf_header(p, IP_HLEN)) {               //移动payload指针，指向pbuf中的IP首部
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output: not enough room for IP header in pbuf\n"));

      IP_STATS_INC(ip.err);
      snmp_inc_ipoutdiscards();
      return ERR_BUF;                            //失败,返回pbuf空间错误
    }

    iphdr = (struct ip_hdr *)p->payload;         //iphdr指向数据报首部
    
    LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
               (p->len >= sizeof(struct ip_hdr)));

    IPH_TTL_SET(iphdr, ttl);                     //填写TTL字段
    IPH_PROTO_SET(iphdr, proto);                 //填写协议字段
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += LWIP_MAKE_U16(proto, ttl);
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* dest cannot be NULL here */
    ip_addr_copy(iphdr->dest, *dest);            //填写目的IP地址
    
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);         //填写版本号+首部长度+服务类型
    IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += LWIP_MAKE_U16(tos, iphdr->_v_hl);
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_LEN_SET(iphdr, htons(p->tot_len));      //填写数据报总长度
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_OFFSET_SET(iphdr, 0);                   //填写标志位和片偏移字段，都为0
    IPH_ID_SET(iphdr, htons(ip_id));            //填写标识字段
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
    ++ip_id;                                    //数据报编号值加1

    if (ip_addr_isany(src)) 
	{                                           //若src为空，则将源IP地址填写为网络接口的IP地址
      ip_addr_copy(iphdr->src, netif->ip_addr);
    } 
	else 
    {                                           //若src不为空，则直接填写源IP地址
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
    IPH_CHKSUM_SET(iphdr, 0);                             //清0校验和字段
    
#if CHECKSUM_GEN_IP
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));   //计算并填写首部校验和
#endif

#endif /* CHECKSUM_GEN_IP_INLINE */
  }
  else 
  {
    /* IP header already included in p */
    iphdr = (struct ip_hdr *)p->payload;
    ip_addr_copy(dest_addr, iphdr->dest);
    dest = &dest_addr;                     //只是用变量dest记录下数据报中的目的IP地址
  }
  
  IP_STATS_INC(ip.xmit);
  
  LWIP_DEBUGF(IP_DEBUG, ("ip_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], netif->num));
  ip_debug_print(p);
  
  //下面开始发送IP数据报，分三种情况来处理
#if ENABLE_LOOPBACK
  if (ip_addr_cmp(dest, &netif->ip_addr))              // 如果目的 IP 地址是本网卡的地址
  {
    /* Packet to self, enqueue it for loopback */
    LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
    return netif_loop_output(netif, p, dest);          //则调用环回输入，这个函数见第8章
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
  if (netif->mtu && (p->tot_len > netif->mtu))   //如果数据报太大(大于接口的mtu)
  {
    return ip_frag(p, netif, dest);              //则调用函数ip_frag对数据报分片发送
  }
#endif /* IP_FRAG */
  
  LWIP_DEBUGF(IP_DEBUG, ("netif->output()"));
  //剩下的情况，直接调用接口注册的output函数发送数据报
  //netif->output=etharp_output;//IP层发送数据包函数，这里使用ARP的相关函数
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
 //函数功能 : 被传输层协议调用以发送数据报，该函数查找网络接口并调用函数ip_output_if完成最终的发送工作
 //参数 p : 传输层协议需要发送的数据包pbuf,payload指针已指向了协议首部
 //参数 src : 源IP地址，若为NULL，则使用网络接口结构中保存的IP地址
 //参数 dest : 目的IP地址，若为IP_HDRINCL,则表示p中已经有了填好的IP
 //参数报首部，且payload指针也已经指向了IP首部
 //参数ttl,tos,proto; IP首部中的TTL字段、服务类型和协议类型值
err_t
ip_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
          u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
  LWIP_ASSERT("p->ref == 1", p->ref == 1);

  //根据目的IP地址为数据报寻找一个合适的网络接口
  if ((netif = ip_route(dest)) == NULL) { //若找到，变量netif指向对应的接口结构
    LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
      ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;      //找不到，返回接口错误
  }

  //否则，增加netif为参数调用函数if_output_if
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
