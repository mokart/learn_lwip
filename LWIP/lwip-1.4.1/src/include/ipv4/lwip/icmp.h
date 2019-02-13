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

//首先是宏定义，定义常见的ICMP报文类型，如表11-1所示
#define ICMP_ER   0    /* echo reply */ //回送回答
#define ICMP_DUR  3    /* destination unreachable *///目的站不可达
#define ICMP_SQ   4    /* source quench *///源站抑制
#define ICMP_RD   5    /* redirect *///重定向
#define ICMP_ECHO 8    /* echo *///回送请求
#define ICMP_TE  11    /* time exceeded *///数据报超时
#define ICMP_PP  12    /* parameter problem *///数据报参数错误
#define ICMP_TS  13    /* timestamp *///时间戳请求
#define ICMP_TSR 14    /* timestamp reply *///时间戳回答
#define ICMP_IRQ 15    /* information request *///信息请求
#define ICMP_IR  16    /* information reply *///信息回答

//枚举类型，定义目的站不可达报文中的代码字段常用取值，如表11-2所示
enum icmp_dur_type {
  ICMP_DUR_NET   = 0,  /* net unreachable *///网络不可达
  ICMP_DUR_HOST  = 1,  /* host unreachable *///主机不可达
  ICMP_DUR_PROTO = 2,  /* protocol unreachable *///协议不可达
  ICMP_DUR_PORT  = 3,  /* port unreachable *///端口不可达
  ICMP_DUR_FRAG  = 4,  /* fragmentation needed and DF set *///需要分片但不分片位置位
  ICMP_DUR_SR    = 5   /* source route failed *///源路由失败
};

//枚举类型，定义数据报超时报文中的代码字段取值，如表11-3所示
enum icmp_te_type {
  ICMP_TE_TTL  = 0,    /* time to live exceeded in transit *///生存时间计数器超时
  ICMP_TE_FRAG = 1     /* fragment reassembly time exceeded *///分片重装超时
};

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
/** This is the standard ICMP header only that the u32_t data
 *  is splitted to two u16_t like ICMP echo needs it.
 *  This header is also used for other ICMP types that do not
 *  use the data part.
 */
 //定义ICMP回送请求报文首部结构，由于所有类型ICMP报文首部都有很大的相似性
 //所以这个结构也可以用于其他类型的ICMP报文
PACK_STRUCT_BEGIN
struct icmp_echo_hdr {                      //参见图11-5
  PACK_STRUCT_FIELD(u8_t type);    //类型
  PACK_STRUCT_FIELD(u8_t code);    //代码
  PACK_STRUCT_FIELD(u16_t chksum); //校验和
  PACK_STRUCT_FIELD(u16_t id);     //标识符
  PACK_STRUCT_FIELD(u16_t seqno);  //序号
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
	
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

//定义两个宏，用于读取ICMP首部中的字段
#define ICMPH_TYPE(hdr) ((hdr)->type)
#define ICMPH_CODE(hdr) ((hdr)->code)

/** Combines type and code to an u16_t */

//定义两个宏，用于向ICMP首部字段中写入相应值
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
