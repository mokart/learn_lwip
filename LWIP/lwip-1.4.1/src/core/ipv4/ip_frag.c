/**
 * @file
 * This is the IPv4 packet segmentation and reassembly implementation.
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
 * Author: Jani Monoses <jani@iv.ro> 
 *         Simon Goldschmidt
 * original reassembly code by Adam Dunkels <adam@sics.se>
 * 
 */

#include "lwip/opt.h"
#include "lwip/ip_frag.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/snmp.h"
#include "lwip/stats.h"
#include "lwip/icmp.h"

#include <string.h>

#if IP_REASSEMBLY
/**
 * The IP reassembly code currently has the following limitations:
 * - IP header options are not supported
 * - fragments must not overlap (e.g. due to different routes),
 *   currently, overlapping or duplicate fragments are thrown away
 *   if IP_REASS_CHECK_OVERLAP=1 (the default)!
 *
 * @todo: work with IP header options
 */

/** Setting this to 0, you can turn off checking the fragments for overlapping
 * regions. The code gets a little smaller. Only use this if you know that
 * overlapping won't occur on your network! */
#ifndef IP_REASS_CHECK_OVERLAP
#define IP_REASS_CHECK_OVERLAP 1
#endif /* IP_REASS_CHECK_OVERLAP */

/** Set to 0 to prevent freeing the oldest datagram when the reassembly buffer is
 * full (IP_REASS_MAX_PBUFS pbufs are enqueued). The code gets a little smaller.
 * Datagrams will be freed by timeout only. Especially useful when MEMP_NUM_REASSDATA
 * is set to 1, so one datagram can be reassembled at a time, only. */
#ifndef IP_REASS_FREE_OLDEST
#define IP_REASS_FREE_OLDEST 1
#endif /* IP_REASS_FREE_OLDEST */

//����꣬����ip_reassdata�ṹ��flags�ֶΣ���ʾ�����ݱ�
#define IP_REASS_FLAG_LASTFRAG 0x01

/** This is a helper struct which holds the starting
 * offset and the ending offset of this fragment to
 * easily chain the fragments.
 * It has the same packing requirements as the IP header, since it replaces
 * the IP header in memory in incoming fragments (after copying it) to keep
 * track of the various fragments. (-> If the IP header doesn't need packing,
 * this struct doesn't need packing, too.)
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip_reass_helper {
  PACK_STRUCT_FIELD(struct pbuf *next_pbuf);  //ָ����һ����Ƭ
  PACK_STRUCT_FIELD(u16_t start);             //��Ƭ�����ݵ���ʼλ��
  PACK_STRUCT_FIELD(u16_t end);               //��Ƭ�����ݵĽ���λ��
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define IP_ADDRESSES_AND_ID_MATCH(iphdrA, iphdrB)  \
  (ip_addr_cmp(&(iphdrA)->src, &(iphdrB)->src) && \
   ip_addr_cmp(&(iphdrA)->dest, &(iphdrB)->dest) && \
   IPH_ID(iphdrA) == IPH_ID(iphdrB)) ? 1 : 0

/* global variables */
static struct ip_reassdata *reassdatagrams;     //��ͷ
//����ȫ�ֱ��������ڼ�¼��ǰ������װ�ṹip_reassdata�����ӵ�pbuf����
static u16_t ip_reass_pbufcount;

/* function prototypes */
static void ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);
static int ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);

/**
 * Reassembly timer base function
 * for both NO_SYS == 0 and 1 (!).
 *
 * Should be called every 1000 msec (defined by IP_TMR_INTERVAL).
 */
void
ip_reass_tmr(void)
{
  struct ip_reassdata *r, *prev = NULL;

  r = reassdatagrams;                                 //ָ�������ײ�
  while (r != NULL) 
  {
    /* Decrement the timer. Once it reaches 0,
     * clean up the incomplete fragment assembly */
    if (r->timer > 0)                     //ʣ������ʱ�����0�������1
	{
      r->timer--;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer dec %"U16_F"\n",(u16_t)r->timer));
      prev = r;                           //prev ָ��ǰ��װ�ṹ��ip_ressdata
      r = r->next;                        //r ָ����һ����װ�ṹ��ip_reassdata
    } 
	else             
	{
      //ʣ������ʱ��Ϊ0���� :
      /* reassembly timed out */
      struct ip_reassdata *tmp;         //ָ��ǰ��Ҫ�ͷŵ� ip_reassdata �ṹ
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer timed out\n"));
      tmp = r;
      /* get the next pointer before freeing */
      r = r->next;                      //rָ����һ����װ�ṹ��ip_reassdata
      /* free the helper struct and all enqueued pbufs */
      ip_reass_free_complete_datagram(tmp, prev);    //�ͷŵ�ǰ�ṹ�����ϵ�����pbuf
     }
   }
}

/**
 * Free a datagram (struct ip_reassdata) and all its pbufs.
 * Updates the total count of enqueued pbufs (ip_reass_pbufcount),
 * SNMP counters and sends an ICMP time exceeded packet.
 *
 * @param ipr datagram to free
 * @param prev the previous datagram in the linked list
 * @return the number of pbufs freed
 */
static int
ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  u16_t pbufs_freed = 0;
  u8_t clen;
  struct pbuf *p;
  struct ip_reass_helper *iprh;

  LWIP_ASSERT("prev != ipr", prev != ipr);
  if (prev != NULL) {
    LWIP_ASSERT("prev->next == ipr", prev->next == ipr);
  }

  snmp_inc_ipreasmfails();
#if LWIP_ICMP
  iprh = (struct ip_reass_helper *)ipr->p->payload;
  if (iprh->start == 0) {
    /* The first fragment was received, send ICMP time exceeded. */
    /* First, de-queue the first pbuf from r->p. */
    p = ipr->p;
    ipr->p = iprh->next_pbuf;
    /* Then, copy the original header into it. */
    SMEMCPY(p->payload, &ipr->iphdr, IP_HLEN);
    icmp_time_exceeded(p, ICMP_TE_FRAG);
    clen = pbuf_clen(p);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed += clen;
    pbuf_free(p);
  }
#endif /* LWIP_ICMP */

  /* First, free all received pbufs.  The individual pbufs need to be released 
     separately as they have not yet been chained */
  p = ipr->p;
  while (p != NULL) {
    struct pbuf *pcur;
    iprh = (struct ip_reass_helper *)p->payload;
    pcur = p;
    /* get the next pointer before freeing */
    p = iprh->next_pbuf;
    clen = pbuf_clen(pcur);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed += clen;
    pbuf_free(pcur);
  }
  /* Then, unchain the struct ip_reassdata from the list and free it. */
  ip_reass_dequeue_datagram(ipr, prev);
  LWIP_ASSERT("ip_reass_pbufcount >= clen", ip_reass_pbufcount >= pbufs_freed);
  ip_reass_pbufcount -= pbufs_freed;

  return pbufs_freed;
}

#if IP_REASS_FREE_OLDEST
/**
 * Free the oldest datagram to make room for enqueueing new fragments.
 * The datagram 'fraghdr' belongs to is not freed!
 *
 * @param fraghdr IP header of the current fragment
 * @param pbufs_needed number of pbufs needed to enqueue
 *        (used for freeing other datagrams if not enough space)
 * @return the number of pbufs freed
 */
static int
ip_reass_remove_oldest_datagram(struct ip_hdr *fraghdr, int pbufs_needed)
{
  /* @todo Can't we simply remove the last datagram in the
   *       linked list behind reassdatagrams?
   */
  struct ip_reassdata *r, *oldest, *prev;
  int pbufs_freed = 0, pbufs_freed_current;
  int other_datagrams;

  /* Free datagrams until being allowed to enqueue 'pbufs_needed' pbufs,
   * but don't free the datagram that 'fraghdr' belongs to! */
  do {
    oldest = NULL;
    prev = NULL;
    other_datagrams = 0;
    r = reassdatagrams;
    while (r != NULL) {
      if (!IP_ADDRESSES_AND_ID_MATCH(&r->iphdr, fraghdr)) {
        /* Not the same datagram as fraghdr */
        other_datagrams++;
        if (oldest == NULL) {
          oldest = r;
        } else if (r->timer <= oldest->timer) {
          /* older than the previous oldest */
          oldest = r;
        }
      }
      if (r->next != NULL) {
        prev = r;
      }
      r = r->next;
    }
    if (oldest != NULL) {
      pbufs_freed_current = ip_reass_free_complete_datagram(oldest, prev);
      pbufs_freed += pbufs_freed_current;
    }
  } while ((pbufs_freed < pbufs_needed) && (other_datagrams > 1));
  return pbufs_freed;
}
#endif /* IP_REASS_FREE_OLDEST */

/**
 * Enqueues a new fragment into the fragment queue
 * @param fraghdr points to the new fragments IP hdr
 * @param clen number of pbufs needed to enqueue (used for freeing other datagrams if not enough space)
 * @return A pointer to the queue location into which the fragment was enqueued
 */
static struct ip_reassdata*
ip_reass_enqueue_new_datagram(struct ip_hdr *fraghdr, int clen)
{
  struct ip_reassdata* ipr;
  /* No matching previous fragment found, allocate a new reassdata struct */
  ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
  if (ipr == NULL) {
#if IP_REASS_FREE_OLDEST
    if (ip_reass_remove_oldest_datagram(fraghdr, clen) >= clen) {
      ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
    }
    if (ipr == NULL)
#endif /* IP_REASS_FREE_OLDEST */
    {
      IPFRAG_STATS_INC(ip_frag.memerr);
      LWIP_DEBUGF(IP_REASS_DEBUG,("Failed to alloc reassdata struct\n"));
      return NULL;
    }
  }
  memset(ipr, 0, sizeof(struct ip_reassdata));
  ipr->timer = IP_REASS_MAXAGE;

  /* enqueue the new structure to the front of the list */
  ipr->next = reassdatagrams;
  reassdatagrams = ipr;
  /* copy the ip header for later tests and input */
  /* @todo: no ip options supported? */
  SMEMCPY(&(ipr->iphdr), fraghdr, IP_HLEN);
  return ipr;
}

/**
 * Dequeues a datagram from the datagram queue. Doesn't deallocate the pbufs.
 * @param ipr points to the queue entry to dequeue
 */
static void
ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  
  /* dequeue the reass struct  */
  if (reassdatagrams == ipr) {
    /* it was the first in the list */
    reassdatagrams = ipr->next;
  } else {
    /* it wasn't the first, so it must have a valid 'prev' */
    LWIP_ASSERT("sanity check linked list", prev != NULL);
    prev->next = ipr->next;
  }

  /* now we can free the ip_reass struct */
  memp_free(MEMP_REASSDATA, ipr);
}

/**
 * Chain a new pbuf into the pbuf list that composes the datagram.  The pbuf list
 * will grow over time as  new pbufs are rx.
 * Also checks that the datagram passes basic continuity checks (if the last
 * fragment was received at least once).
 * @param root_p points to the 'root' pbuf for the current datagram being assembled.
 * @param new_p points to the pbuf for the current fragment
 * @return 0 if invalid, >0 otherwise
 */
 //�������� : ����Ƭ���뵽ip_reassdata����װ����������Ƿ����յ����ݱ������з�Ƭ
 //����ipr  : ���ݱ���װ��ip_reassdata�ṹָ��
 //���� new_p: ��Ƭ���ݱ�pbufָ��
 //����ֵ  : �����Ƭ��ص����ݱ����з��鶼���յ����򷵻�1�����򷵻�0
static int
ip_reass_chain_frag_into_datagram_and_validate(struct ip_reassdata *ipr, struct pbuf *new_p)
{
  struct ip_reass_helper *iprh, *iprh_tmp, *iprh_prev=NULL;
  struct pbuf *q;
  u16_t offset,len;
  struct ip_hdr *fraghdr;
  int valid = 1;                        //��־�Ƿ����з�Ƭ�����յ�

  /* Extract length and fragment offset from current fragment */
  fraghdr = (struct ip_hdr*)new_p->payload;                      //ָ���Ƭ���ײ�����
  len = ntohs(IPH_LEN(fraghdr)) - IPH_HL(fraghdr) * 4;           //��Ƭ�����ݵ��ܳ���
  offset = (ntohs(IPH_OFFSET(fraghdr)) & IP_OFFMASK) * 8;        //��Ƭ�����ݱ��е���ʼλ��

  /* overwrite the fragment's ip header from the pbuf with our helper struct,
   * and setup the embedded helper structure. */
  /* make sure the struct ip_reass_helper fits into the IP header */
  LWIP_ASSERT("sizeof(struct ip_reass_helper) <= IP_HLEN",
              sizeof(struct ip_reass_helper) <= IP_HLEN);
  //����Ƭ�ײ�ǰ8���ֽ�ǿ��ת��Ϊip_reass_helper�ṹ��������װ����
  iprh = (struct ip_reass_helper*)new_p->payload;
  iprh->next_pbuf = NULL;                           //ָ����һ����Ƭ�ṹ
  iprh->start = offset;                             //��Ƭ���������������ݱ��е���ʼλ��
  iprh->end = offset + len;                         //��Ƭ���������������ݱ��еĽ���λ��

  /* Iterate through until we either get to the end of the list (append),
   * or we find on with a larger offset (insert). */
   //��������Ҫ����ip_reassdata�ṹ����װ����Ϊ��Ƭ����һ�����ʵ�λ��
   //�����������У�����Ҫ����valid��ֵ�����ж����ݱ����еķ�Ƭ����״��
  for (q = ipr->p; q != NULL;) {                      //�ӵ�һ����Ƭ��ʼ
    iprh_tmp = (struct ip_reass_helper*)q->payload;     //��ǰ��Ƭ��ip_reass_helper�ṹ
    if (iprh->start < iprh_tmp->start) {                //����·�Ƭ��������ʼλ�ø��ͣ����ҵ�λ����
      /* the new pbuf should be inserted before this */
      iprh->next_pbuf = q;                              //�·�Ƭ��next_pbufָ��ָ��p
      if (iprh_prev != NULL) {                          //��ǰ��Ƭ���ǵ�һ����Ƭ
        /* not the fragment with the lowest offset */
#if IP_REASS_CHECK_OVERLAP
        if ((iprh->start < iprh_prev->end) || (iprh->end > iprh_tmp->start)) {
          /* fragment overlaps with previous or following, throw away */
          goto freepbuf;
        }
#endif /* IP_REASS_CHECK_OVERLAP */
        iprh_prev->next_pbuf = new_p;         //����ǰһ����Ƭ��next_pbufָ��new_p
      } else {                                //��ǰ��Ƭ�ǵ�һ����Ƭ����ip_reassdata�ṹ��pָ��ָ���·�Ƭ
        /* fragment with the lowest offset */
        ipr->p = new_p;
      }
      break;                                  //������ϣ�����
    } else if(iprh->start == iprh_tmp->start) {    //����Ƭ������ʼλ���ص������Ƭ�Ƕ����
      /* received the same datagram twice: no need to keep the datagram */
      goto freepbuf;                            //����freepbuf��ɾ����Ƭ�����˳�
#if IP_REASS_CHECK_OVERLAP
    } else if(iprh->start < iprh_tmp->end) {
      /* overlap: no need to keep the new datagram */
      goto freepbuf;
#endif /* IP_REASS_CHECK_OVERLAP */
    } else {                                        //�������ж��·�Ƭ�Ĳ���λ��Ӧ���ڵ�ǰ��Ƭλ��֮���ĳ��
      /* Check if the fragments received so far have no wholes. */
      if (iprh_prev != NULL) {                   //�жϵ�ǰ��Ƭ��ǰһ����Ƭ�������Ƿ�Ϊ������
        if (iprh_prev->end != iprh_tmp->start) {       //��������˵�����з�Ƭδ�յ���valid=0
          /* There is a fragment missing between the current
           * and the previous fragment */
          valid = 0;
        }
      }
    }
    q = iprh_tmp->next_pbuf;                        //ָ���������һ����Ƭ
    iprh_prev = iprh_tmp;                           //��¼��ǰ��Ƭ
  }

  /* If q is NULL, then we made it to the end of the list. Determine what to do now */
  //�жϲ��빤���Ƿ���ɣ���q�Ƿ�Ϊ�գ���Ϊ�գ����·�Ƭ���뵽����β��
  if (q == NULL) {
    if (iprh_prev != NULL) {                       //iprh_prev��ָ�������е����һ����Ƭ
      /* this is (for now), the fragment with the highest offset:
       * chain it to the last fragment */
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("check fragments don't overlap", iprh_prev->end <= iprh->start);
#endif /* IP_REASS_CHECK_OVERLAP */
      iprh_prev->next_pbuf = new_p;                 //�·�Ƭ���뵽����β��
      if (iprh_prev->end != iprh->start) {           //������һ����Ƭ���·�Ƭ�����ݲ�����
        valid = 0;                                  //���з���δ���յ�
      }
    } else {                                       //������û���κη�Ƭ
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("no previous fragment, this must be the first fragment!",
        ipr->p == NULL);
#endif /* IP_REASS_CHECK_OVERLAP */
      /* this is the first fragment we ever received for this ip datagram */
      ipr->p = new_p;                               //�·�Ƭ��Ϊ��װ����ĵ�һ����Ƭ
    }
  }

  /* At this point, the validation part begins: */
  /* If we already received the last fragment */
  //����ж����ݱ������з�Ƭ�Ƿ��Ѿ��յ�
  if ((ipr->flags & IP_REASS_FLAG_LASTFRAG) != 0) { //���ж����һ����Ƭ�Ƿ��յ�
    /* and had no wholes so far */
    if (valid) {                  //���һ����Ƭ�Ѿ��յ����ҷ�Ƭ������Ȼ����
      /* then check if the rest of the fragments is here */
      /* Check if the queue starts with the first datagram */
      if (((struct ip_reass_helper*)ipr->p->payload)->start != 0) {  //�жϵ�һ����Ƭ�Ƿ��յ�
        valid = 0;
      } else {                    //��һ����ƬҲ�Ѿ��յ�
        /* and check that there are no wholes after this datagram */
        iprh_prev = iprh;         //���·�Ƭ�Ĳ���λ�ÿ�ʼ������������з�Ƭ�Ƿ�����
        q = iprh->next_pbuf;      //ָ����һ����Ƭ
        while (q != NULL) {
          iprh = (struct ip_reass_helper*)q->payload;     //ָ���Ƭ��ip_reass_helper�ṹ
          if (iprh_prev->end != iprh->start) {            //���������������ѭ��
            valid = 0;
            break;
          }
          iprh_prev = iprh;                               //��¼��ǰ��Ƭ
          q = iprh->next_pbuf;                            //�����һ����Ƭ
        }
        /* if still valid, all fragments are received
         * (because to the MF==0 already arrived */
        if (valid) {                                    
          LWIP_ASSERT("sanity check", ipr->p != NULL);
          LWIP_ASSERT("sanity check",
            ((struct ip_reass_helper*)ipr->p->payload) != iprh);
          LWIP_ASSERT("validate_datagram:next_pbuf!=NULL",
            iprh->next_pbuf == NULL);
          LWIP_ASSERT("validate_datagram:datagram end!=datagram len",
            iprh->end == ipr->datagram_len);
        }
      }
    }
    /* If valid is 0 here, there are some fragments missing in the middle
     * (since MF == 0 has already arrived). Such datagrams simply time out if
     * no more fragments are received... */
    return valid;                                             //����valid��ֵ
  }
  /* If we come here, not all fragments were received, yet! */
  return 0; /* not yet valid! */                        //���ݱ����һ�����黹δ�յ���ֱ�ӷ���0
#if IP_REASS_CHECK_OVERLAP
freepbuf:
  ip_reass_pbufcount -= pbuf_clen(new_p);              //����ȫ�ֱ�����ֵ
  pbuf_free(new_p);                                    //�ͷŷ�Ƭ���ݱ�pbuf
  return 0;                                            //����0
#endif /* IP_REASS_CHECK_OVERLAP */
}

/**
 * Reassembles incoming IP fragments into an IP datagram.
 *
 * @param p points to a pbuf chain of the fragment
 * @return NULL if reassembly is incomplete, ? otherwise
 */
 //�������� : ��װ��Ƭ���ݱ�
 //������� : ��Ƭ���ݱ�pbuf
 //������� : ��ĳ�����ݱ���װ��ɣ��򷵻�����pbuf��ָ�룻���򷵻�NULL
struct pbuf *
ip_reass(struct pbuf *p)
{
  struct pbuf *r;                                //pbuf��ָ��
  struct ip_hdr *fraghdr;                        //IP�ײ���ָ��
  struct ip_reassdata *ipr;                      //��װ�ṹָ��
  struct ip_reass_helper *iprh;                  //��װhelperָ��
  u16_t offset, len;                             //��¼��Ƭ��ƫ�����ͷ�Ƭ�е����ݳ���
  u8_t clen;                                     //��¼��Ƭռ�õ�pbuf����
  struct ip_reassdata *ipr_prev = NULL;          //��¼ǰһ����װ�ṹ

  IPFRAG_STATS_INC(ip_frag.recv);
  snmp_inc_ipreasmreqds();

  fraghdr = (struct ip_hdr*)p->payload;          //�õ���Ƭ���ݱ��ײ�

  if ((IPH_HL(fraghdr) * 4) != IP_HLEN) {        //���ײ����Ȳ�Ϊ20�������nullreturn��
    LWIP_DEBUGF(IP_REASS_DEBUG,("ip_reass: IP options currently not supported!\n"));
    IPFRAG_STATS_INC(ip_frag.err);
    goto nullreturn;
  }

  offset = (ntohs(IPH_OFFSET(fraghdr)) & IP_OFFMASK) * 8;   //�õ���Ƭƫ����(�ֽ�) 
  len = ntohs(IPH_LEN(fraghdr)) - IPH_HL(fraghdr) * 4;      //�õ���Ƭ���ݳ���
                                                            
  /* Check if we are allowed to enqueue more datagrams. */  
  clen = pbuf_clen(p);                                      //�����Ƭռ�õ�pbuf��

  //�����ж������clen��pbuf���뵽��װ�����У�����װ����ռ�õ�pbuf�ܸ���
  //�Ƿ񳬹���ϵͳ�涨�����޸��� IP_REASS_MAX_PBUFS ,���ǣ������ѡ���ͷ�
  //�������ϵ�ip_reassdata�����ϵ�����pbuf���ٽ����ж�
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {     //���������������
#if IP_REASS_FREE_OLDEST 
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen) ||    //�ͷ����ϵ���װ�ṹ
        ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))   //���ж�
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* No datagram could be freed and still too many pbufs enqueued */
      LWIP_DEBUGF(IP_REASS_DEBUG,("ip_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
        ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
      /* @todo: send ICMP time exceeded here? */
      /* drop this pbuf */
      goto nullreturn;
    }
  }

  /* Look for the datagram the fragment belongs to in the current datagram queue,
   * remembering the previous in the queue for later dequeueing. */
   //�������Ƭ���ݱ������˲��뵽��װ�����е�������������ƥ���ip_reassdata�ṹ
  for (ipr = reassdatagrams; ipr != NULL; ipr = ipr->next) {                 //���β���
    /* Check if the incoming fragment matches the one currently present
       in the reassembly buffer. If so, we proceed with copying the
       fragment into the buffer. */
    if (IP_ADDRESSES_AND_ID_MATCH(&ipr->iphdr, fraghdr)) {                   //��ƥ��
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass: matching previous fragment ID=%"X16_F"\n",
        ntohs(IPH_ID(fraghdr))));
      IPFRAG_STATS_INC(ip_frag.cachehit);
      break;
    }
    ipr_prev = ipr;               //����ipr_prev���ڼ�¼ǰһ��ip_reassdata�ṹ
  }

  if (ipr == NULL) {              //���δ�ҵ�ƥ��Ľṹ��˵�������Ƭ��һ�������ݱ��ķ�Ƭ��Ϊ��
  /* Enqueue a new datagram into the datagram queue */
    ipr = ip_reass_enqueue_new_datagram(fraghdr, clen);//��Ƭ�½�һ��ip_reassdata�ṹ
    /* Bail if unable to enqueue */
    if(ipr == NULL) {                                  //�½�ʧ��
      goto nullreturn;
    }
  } else {                                         //�ҵ�ƥ��Ľṹ���Ҹ÷���Ϊĳ�����ݱ��ĵ�һ����Ƭ(Ƭƫ��Ϊ0)
    if (((ntohs(IPH_OFFSET(fraghdr)) & IP_OFFMASK) == 0) && 
      ((ntohs(IPH_OFFSET(&ipr->iphdr)) & IP_OFFMASK) != 0)) {
      /* ipr->iphdr is not the header from the first fragment, but fraghdr is
       * -> copy fraghdr into ipr->iphdr since we want to have the header
       * of the first fragment (for ICMP time exceeded and later, for copying
       * all options, if supported)*/
       //�����ǽ���Ƭ���ײ�������ip_reassdata�ṹ�м�¼�ײ���iphdr�ֶ���
      SMEMCPY(&ipr->iphdr, fraghdr, IP_HLEN);
    }
  }
  /* Track the current number of pbufs current 'in-flight', in order to limit 
  the number of fragments that may be enqueued at any one time */
  //����������½�����ң����Ƕ�Ϊ��Ƭ�õ���һ��ip_reassdata�ṹ
  ip_reass_pbufcount += clen;                     //ȫ�ֱ������ӣ���¼pbuf�ܸ���

  /* At this point, we have either created a new entry or pointing 
   * to an existing one */

  /* check for 'no more fragments', and update queue entry*/
  //�жϷ�Ƭ�Ƿ�Ϊ���ݱ������һ����Ƭ��������ip_reassdata�ṹ������ֶ�
  if ((IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0) { //�������һ����Ƭ
    ipr->flags |= IP_REASS_FLAG_LASTFRAG;             //����flags���յ����һ����Ƭ
    ipr->datagram_len = offset + len;                 //datagram_len����Ϊ�����ܳ���
    LWIP_DEBUGF(IP_REASS_DEBUG,
     ("ip_reass: last fragment seen, total len %"S16_F"\n",
      ipr->datagram_len));
  }
  /* find the right place to insert this pbuf */
  /* @todo: trim pbufs if fragments are overlapping */
  //���ú�������Ƭ���뵽��װ�ṹ�������У�ͬʱ�������ݱ����з�Ƭ�Ƿ��ѵ���
  if (ip_reass_chain_frag_into_datagram_and_validate(ipr, p)) {   //�����з�Ƭ�ѵ���
    /* the totally last fragment (flag more fragments = 0) was received at least
     * once AND all fragments are received */
    ipr->datagram_len += IP_HLEN;               //datagram_len����Ϊ���ݱ��ܳ���

    /* save the second pbuf before copying the header over the pointer */
    r = ((struct ip_reass_helper*)ipr->p->payload)->next_pbuf;   //rָ��ڶ�����Ƭpbuf

    /* copy the original ip header back to the first pbuf */
    fraghdr = (struct ip_hdr*)(ipr->p->payload);                 //ָ���һ����Ƭ���ײ�
    SMEMCPY(fraghdr, &ipr->iphdr, IP_HLEN);                      //��IP�ײ���������һ����Ƭ��
    IPH_LEN_SET(fraghdr, htons(ipr->datagram_len));              //�����ܳ����ֶ�
    IPH_OFFSET_SET(fraghdr, 0);                                  //IP��Ƭ��ص��ֶ�ȫ����0
    IPH_CHKSUM_SET(fraghdr, 0);                                  //У����ֶ���0
    /* @todo: do we need to set calculate the correct checksum? */
    IPH_CHKSUM_SET(fraghdr, inet_chksum(fraghdr, IP_HLEN));      //������дУ���

    p = ipr->p;                  //ָ���һ����Ƭ������װ������ݱ���ʼpbuf

    /* chain together the pbufs contained within the reass_data list. */
    while(r != NULL) {        //�ӵڶ�����Ƭ��ʼ������������Ƭpbuf��payloadָ��
      iprh = (struct ip_reass_helper*)r->payload;     //��Ƭ��helper�ṹ����ʼ��

      /* hide the ip header for every succeding fragment */
      pbuf_header(r, -IP_HLEN);                       //����payloadָ�룬���ط�Ƭ�е�IP�ײ�
      pbuf_cat(p, r);                                 //����������Ƭ��pbuf
      r = iprh->next_pbuf;                            //rָ����һ����Ƭ��ʼpbuf
    }

    /* release the sources allocate for the fragment queue entry */
    //������������ݱ�����װ����������ˣ���ʱ��Ҫɾ������reassdatagrams����
    //���ݱ���Ӧ��ip_reassdata�ṹ���������ݱ�pbufָ�뷵��
    ip_reass_dequeue_datagram(ipr, ipr_prev);   //��������ɾ��ip_reassddata�ṹ

    /* and adjust the number of pbufs currently queued for reassembly. */
    ip_reass_pbufcount -= pbuf_clen(p);        //����ȫ�ֱ���ֵ

    /* Return the pbuf chain */
    return p;                                  //������װ�õ����ݱ�pbuf
  }
  /* the datagram is not (yet?) reassembled completely */
  LWIP_DEBUGF(IP_REASS_DEBUG,("ip_reass_pbufcount: %d out\n", ip_reass_pbufcount));
  return NULL;                  //����˵�����ݱ����з�Ƭδ�յ�������NULL

nullreturn:                      //���ݱ��������װ����������
  LWIP_DEBUGF(IP_REASS_DEBUG,("ip_reass: nullreturn\n"));
  IPFRAG_STATS_INC(ip_frag.drop);
  pbuf_free(p);                  //ɾ�����ݱ�pbuf
  return NULL;                   //����NULL
}
#endif /* IP_REASSEMBLY */

//����һ��ȫ���͵����飬�����СΪIP�����������Ƭ��С��ÿ����Ƭ�ᱻ�Ⱥ�
//��������������У�Ȼ����
#if IP_FRAG
#if IP_FRAG_USES_STATIC_BUF
static u8_t buf[LWIP_MEM_ALIGN_SIZE(IP_FRAG_MAX_MTU + MEM_ALIGNMENT - 1)];
#else /* IP_FRAG_USES_STATIC_BUF */

#if !LWIP_NETIF_TX_SINGLE_PBUF
/** Allocate a new struct pbuf_custom_ref */
static struct pbuf_custom_ref*
ip_frag_alloc_pbuf_custom_ref(void)
{
  return (struct pbuf_custom_ref*)memp_malloc(MEMP_FRAG_PBUF);
}

/** Free a struct pbuf_custom_ref */
static void
ip_frag_free_pbuf_custom_ref(struct pbuf_custom_ref* p)
{
  LWIP_ASSERT("p != NULL", p != NULL);
  memp_free(MEMP_FRAG_PBUF, p);
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
static void
ipfrag_free_pbuf_custom(struct pbuf *p)
{
  struct pbuf_custom_ref *pcr = (struct pbuf_custom_ref*)p;
  LWIP_ASSERT("pcr != NULL", pcr != NULL);
  LWIP_ASSERT("pcr == p", (void*)pcr == (void*)p);
  if (pcr->original != NULL) {
    pbuf_free(pcr->original);
  }
  ip_frag_free_pbuf_custom_ref(pcr);
}
#endif /* !LWIP_NETIF_TX_SINGLE_PBUF */
#endif /* IP_FRAG_USES_STATIC_BUF */

/**
 * Fragment an IP datagram if too large for the netif.
 *
 * Chop the datagram in MTU sized chunks and send them in order
 * by using a fixed size static memory buffer (PBUF_REF) or
 * point PBUF_REFs into p (depending on IP_FRAG_USES_STATIC_BUF).
 *
 * @param p ip packet to send
 * @param netif the netif on which to send
 * @param dest destination ip address to which to send
 *
 * @return ERR_OK if sent successfully, err_t otherwise
 */
//��������  : �����ݱ�P���з�Ƭ���ͣ��ú�����ip_output_if�б�����
//����p     : ��Ҫ���䷢�͵����ݱ�
//����netif : �������ݱ�������ӿڽṹָ��
//����dest  : Ŀ��IP��ַ
err_t 
ip_frag(struct pbuf *p, struct netif *netif, ip_addr_t *dest)
{
  struct pbuf *rambuf;                    //��Ƭ��pbuf�ṹ
#if IP_FRAG_USES_STATIC_BUF 
  struct pbuf *header;                    //��̫��֡pbuf
#else
#if !LWIP_NETIF_TX_SINGLE_PBUF
  struct pbuf *newpbuf;
#endif
  struct ip_hdr *original_iphdr;
#endif
  struct ip_hdr *iphdr;                   //IP�ײ�ָ��
  u16_t nfb;                              //��Ƭ����������������
  u16_t left, cop;                        //�����͵����ݳ��Ⱥ͵�ǰ���͵����ݳ���
  u16_t mtu = netif->mtu;                 //����ӿ�mtu
  u16_t ofo, omf;                         //��Ƭƫ�����͸����Ƭλ
  u16_t last;                             //�Ƿ�Ϊ���һ����Ƭ
  u16_t poff = IP_HLEN;                   //���͵����ݵ�ԭʼ���ݱ�pbuf�е�ƫ����
  u16_t tmp;
#if !IP_FRAG_USES_STATIC_BUF && !LWIP_NETIF_TX_SINGLE_PBUF
  u16_t newpbuflen = 0;
  u16_t left_to_copy;
#endif

  /* Get a RAM based MTU sized pbuf */
#if IP_FRAG_USES_STATIC_BUF
  /* When using a static buffer, we use a PBUF_REF, which we will
   * use to reference the packet (without link header).
   * Layer and length is irrelevant.
   */
  rambuf = pbuf_alloc(PBUF_LINK, 0, PBUF_REF);    //Ϊ���ݷ�Ƭ����һ��pbuf�ṹ
  if (rambuf == NULL) {                           //����ʧ�ܣ��򷵻�
    LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_frag: pbuf_alloc(PBUF_LINK, 0, PBUF_REF) failed\n"));
    return ERR_MEM;
  }
  rambuf->tot_len = rambuf->len = mtu;             //����pbuf��len��tot_len�ֶ�Ϊ�ӿڵ�MTUֵ
  rambuf->payload = LWIP_MEM_ALIGN((void *)buf);   //payloadָ��ȫ����������

  /* Copy the IP header in it */
  iphdr = (struct ip_hdr *)rambuf->payload;        //�õ���Ƭ���洢����
  SMEMCPY(iphdr, p->payload, IP_HLEN);             //��ԭʼ���ݱ��ײ���������Ƭ���ײ�
#else /* IP_FRAG_USES_STATIC_BUF */
  original_iphdr = (struct ip_hdr *)p->payload;
  iphdr = original_iphdr;
#endif /* IP_FRAG_USES_STATIC_BUF */

  /* Save original offset */
  tmp = ntohs(IPH_OFFSET(iphdr));                 //�ݴ��Ƭ������ֶ�
  ofo = tmp & IP_OFFMASK;                         //�õ���Ƭƫ����(��ԭʼ���ݱ���˵Ӧ��Ϊ0)
  omf = tmp & IP_MF;                              //�õ������Ƭ��־ֵ

  left = p->tot_len - IP_HLEN;                    //���������ݳ���(�ܳ��� - IP�ײ�����)

  nfb = (mtu - IP_HLEN) / 8;                      //һ����Ƭ�п��Դ�ŵ����������(8�ֽ�Ϊ��λ)

  while (left) {                                  //���������ݳ��ȴ���0
    last = (left <= mtu - IP_HLEN);               //�������ͳ���С�ڷ�Ƭ��󳤶ȣ�lastΪ1������Ϊ0

    /* Set new offset and MF flag */
    tmp = omf | (IP_OFFMASK & (ofo));             //�����Ƭ����ֶ�
    if (!last) {                                  //����������һ����Ƭ
      tmp = tmp | IP_MF;                          //������Ƭλ��1
    }

    //�����Ƭ�е����ݳ��ȣ���lastΪ1ʱ��˵����Ƭ��װ������ʣ������
    /* Fill this fragment */
    cop = last ? left : nfb * 8;

#if IP_FRAG_USES_STATIC_BUF
    //��ԭʼ���ݱ��п���cop�ֽڵ����ݵ���Ƭ�У�poff��¼�˿�������ʼλ��
    poff += pbuf_copy_partial(p, (u8_t*)iphdr + IP_HLEN, cop, poff);
#else /* IP_FRAG_USES_STATIC_BUF */
#if LWIP_NETIF_TX_SINGLE_PBUF
    rambuf = pbuf_alloc(PBUF_IP, cop, PBUF_RAM);
    if (rambuf == NULL) 
	{
      return ERR_MEM;
    }
    LWIP_ASSERT("this needs a pbuf in one piece!",
      (rambuf->len == rambuf->tot_len) && (rambuf->next == NULL));
    poff += pbuf_copy_partial(p, rambuf->payload, cop, poff);
    /* make room for the IP header */
    if(pbuf_header(rambuf, IP_HLEN)) {
      pbuf_free(rambuf);
      return ERR_MEM;
    }
    /* fill in the IP header */
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = rambuf->payload;
#else /* LWIP_NETIF_TX_SINGLE_PBUF */
    /* When not using a static buffer, create a chain of pbufs.
     * The first will be a PBUF_RAM holding the link and IP header.
     * The rest will be PBUF_REFs mirroring the pbuf chain to be fragged,
     * but limited to the size of an mtu.
     */
    rambuf = pbuf_alloc(PBUF_LINK, IP_HLEN, PBUF_RAM);
    if (rambuf == NULL) {
      return ERR_MEM;
    }
    LWIP_ASSERT("this needs a pbuf in one piece!",
                (p->len >= (IP_HLEN)));
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = (struct ip_hdr *)rambuf->payload;

    /* Can just adjust p directly for needed offset. */
    p->payload = (u8_t *)p->payload + poff;
    p->len -= poff;

    left_to_copy = cop;
    while (left_to_copy) {
      struct pbuf_custom_ref *pcr;
      newpbuflen = (left_to_copy < p->len) ? left_to_copy : p->len;
      /* Is this pbuf already empty? */
      if (!newpbuflen) {
        p = p->next;
        continue;
      }
      pcr = ip_frag_alloc_pbuf_custom_ref();
      if (pcr == NULL) {
        pbuf_free(rambuf);
        return ERR_MEM;
      }
      /* Mirror this pbuf, although we might not need all of it. */
      newpbuf = pbuf_alloced_custom(PBUF_RAW, newpbuflen, PBUF_REF, &pcr->pc, p->payload, newpbuflen);
      if (newpbuf == NULL) {
        ip_frag_free_pbuf_custom_ref(pcr);
        pbuf_free(rambuf);
        return ERR_MEM;
      }
      pbuf_ref(p);
      pcr->original = p;
      pcr->pc.custom_free_function = ipfrag_free_pbuf_custom;

      /* Add it to end of rambuf's chain, but using pbuf_cat, not pbuf_chain
       * so that it is removed when pbuf_dechain is later called on rambuf.
       */
      pbuf_cat(rambuf, newpbuf);
      left_to_copy -= newpbuflen;
      if (left_to_copy) {
        p = p->next;
      }
    }
    poff = newpbuflen;
#endif /* LWIP_NETIF_TX_SINGLE_PBUF */
#endif /* IP_FRAG_USES_STATIC_BUF */

    /* Correct header */
    IPH_OFFSET_SET(iphdr, htons(tmp));                       //��д��Ƭ����ֶ�
    IPH_LEN_SET(iphdr, htons(cop + IP_HLEN));                //��д�ܳ���
    IPH_CHKSUM_SET(iphdr, 0);                                //��0У���
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));      //����У���

#if IP_FRAG_USES_STATIC_BUF
    if (last) {                                              //��Ϊ���һ����Ƭ�������pbuf��len��tot_len�ֶ�
      pbuf_realloc(rambuf, left + IP_HLEN);
    }

    /* This part is ugly: we alloc a RAM based pbuf for 
     * the link level header for each chunk and then 
     * free it.A PBUF_ROM style pbuf for which pbuf_header
     * worked would make things simpler.
     */
     //������ ������װ����һ�������ķ�Ƭ����Ҫ���÷�Ƭ���ͳ�ȥ������������
     //�ڴ���п���һ��pbuf�ռ䣬����������̫��֡�ײ�
    header = pbuf_alloc(PBUF_LINK, 0, PBUF_RAM);
    if (header != NULL) {                         //����ɹ����������͹���
      pbuf_chain(header, rambuf);                 //������pbuf���ӳ�һ��pbuf����
      netif->output(netif, header, dest);         //���ú�������
      IPFRAG_STATS_INC(ip_frag.xmit);
      snmp_inc_ipfragcreates();
      pbuf_free(header);                           //������ɺ��ͷ�pbuf����
    } 
	else                                           //����̫���ײ��ռ�����ʧ��
    {
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_frag: pbuf_alloc() for header failed\n"));
      pbuf_free(rambuf);                           //�ͷŽṹrambuf
      return ERR_MEM;                              //�����ڴ����
    }
#else /* IP_FRAG_USES_STATIC_BUF */
    /* No need for separate header pbuf - we allowed room for it in rambuf
     * when allocated.
     */
    netif->output(netif, rambuf, dest);            //��ɷ��͹���
    IPFRAG_STATS_INC(ip_frag.xmit);

    /* Unfortunately we can't reuse rambuf - the hardware may still be
     * using the buffer. Instead we free it (and the ensuing chain) and
     * recreate it next time round the loop. If we're lucky the hardware
     * will have already sent the packet, the free will really free, and
     * there will be zero memory penalty.
     */
    
    pbuf_free(rambuf);
#endif /* IP_FRAG_USES_STATIC_BUF */
    left -= cop;                                    //�����͵��ܳ��ȼ���
    ofo += nfb;                                     //��Ƭƫ��������
  }
#if IP_FRAG_USES_STATIC_BUF
  pbuf_free(rambuf);                                //�ͷŽṹrambuf
#endif /* IP_FRAG_USES_STATIC_BUF */
  snmp_inc_ipfragoks();
  return ERR_OK;                                    //����OK
}
#endif /* IP_FRAG */
