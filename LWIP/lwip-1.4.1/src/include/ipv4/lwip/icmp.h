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
#ifndef __LWIP_ICMP_H__
#define __LWIP_ICMP_H__

#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

//�����Ǻ궨�壬���峣����ICMP�������ͣ����11-1��ʾ
#define ICMP_ER   0    /* echo reply */ //���ͻش�
#define ICMP_DUR  3    /* destination unreachable *///Ŀ��վ���ɴ�
#define ICMP_SQ   4    /* source quench *///Դվ����
#define ICMP_RD   5    /* redirect *///�ض���
#define ICMP_ECHO 8    /* echo *///��������
#define ICMP_TE  11    /* time exceeded *///���ݱ���ʱ
#define ICMP_PP  12    /* parameter problem *///���ݱ���������
#define ICMP_TS  13    /* timestamp *///ʱ�������
#define ICMP_TSR 14    /* timestamp reply *///ʱ����ش�
#define ICMP_IRQ 15    /* information request *///��Ϣ����
#define ICMP_IR  16    /* information reply *///��Ϣ�ش�

//ö�����ͣ�����Ŀ��վ���ɴﱨ���еĴ����ֶγ���ȡֵ�����11-2��ʾ
enum icmp_dur_type {
  ICMP_DUR_NET   = 0,  /* net unreachable *///���粻�ɴ�
  ICMP_DUR_HOST  = 1,  /* host unreachable *///�������ɴ�
  ICMP_DUR_PROTO = 2,  /* protocol unreachable *///Э�鲻�ɴ�
  ICMP_DUR_PORT  = 3,  /* port unreachable *///�˿ڲ��ɴ�
  ICMP_DUR_FRAG  = 4,  /* fragmentation needed and DF set *///��Ҫ��Ƭ������Ƭλ��λ
  ICMP_DUR_SR    = 5   /* source route failed *///Դ·��ʧ��
};

//ö�����ͣ��������ݱ���ʱ�����еĴ����ֶ�ȡֵ�����11-3��ʾ
enum icmp_te_type {
  ICMP_TE_TTL  = 0,    /* time to live exceeded in transit *///����ʱ���������ʱ
  ICMP_TE_FRAG = 1     /* fragment reassembly time exceeded *///��Ƭ��װ��ʱ
};

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
/** This is the standard ICMP header only that the u32_t data
 *  is splitted to two u16_t like ICMP echo needs it.
 *  This header is also used for other ICMP types that do not
 *  use the data part.
 */
 //����ICMP�����������ײ��ṹ��������������ICMP�����ײ����кܴ��������
 //��������ṹҲ���������������͵�ICMP����
PACK_STRUCT_BEGIN
struct icmp_echo_hdr {                      //�μ�ͼ11-5
  PACK_STRUCT_FIELD(u8_t type);    //����
  PACK_STRUCT_FIELD(u8_t code);    //����
  PACK_STRUCT_FIELD(u16_t chksum); //У���
  PACK_STRUCT_FIELD(u16_t id);     //��ʶ��
  PACK_STRUCT_FIELD(u16_t seqno);  //���
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
	
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

//���������꣬���ڶ�ȡICMP�ײ��е��ֶ�
#define ICMPH_TYPE(hdr) ((hdr)->type)
#define ICMPH_CODE(hdr) ((hdr)->code)

/** Combines type and code to an u16_t */

//���������꣬������ICMP�ײ��ֶ���д����Ӧֵ
#define ICMPH_TYPE_SET(hdr, t) ((hdr)->type = (t))
#define ICMPH_CODE_SET(hdr, c) ((hdr)->code = (c))


#if LWIP_ICMP /* don't build if not configured for use in lwipopts.h */

void icmp_input(struct pbuf *p, struct netif *inp);
void icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t);

#endif /* LWIP_ICMP */

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_ICMP_H__ */
