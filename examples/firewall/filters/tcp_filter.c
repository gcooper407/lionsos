/*
 * Copyright 2025, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stdint.h>
#include <os/sddf.h>
#include <sddf/util/util.h>
#include <sddf/util/printf.h>
#include <sddf/network/queue.h>
#include <sddf/network/config.h>
#include <sddf/network/util.h>
#include <lions/firewall/config.h>
#include <lions/firewall/common.h>
#include <lions/firewall/filter.h>
#include <lions/firewall/protocols.h>
#include <lions/firewall/queue.h>

__attribute__((__section__(".fw_filter_config"))) fw_filter_config_t filter_config;

__attribute__((__section__(".fw_tcp_filter_config"))) fw_tcp_filter_config_t tcp_config;

__attribute__((__section__(".net_client_config"))) net_client_config_t net_config;

/* Queues for receiving and transmitting packets */
net_queue_handle_t rx_queue;
net_queue_handle_t tx_queue;
fw_queue_handle_t router_queue;

#define FW_DEBUG_OUTPUT 1
#define MAX_OPEN_SYNS_PER_IP 5

/* Holds filFering rules and state */
fw_filter_state_t filter_state;

typedef enum
{
  TCP_STATE_NONE,
  TCP_STATE_SYN_SENT,
  TCP_STATE_SYN_ACK_RECEIVED,
  TCP_STATE_ESTABLISHED
} tcp_state_t;

typedef struct
{
  bool valid;
  uint32_t src_ip;
  uint16_t src_port;
  uint32_t dst_ip;
  uint16_t dst_port;
  tcp_state_t state;
  uint32_t last_seq;
  uint32_t last_ack_seq;
} tcp_conn_state_t;

static tcp_conn_state_t *tcp_conn_table_src;
static tcp_conn_state_t *tcp_conn_table_dst;

static int count_open_syns(uint32_t src_ip)
{
  int count = 0;
  for (int i = 0; i < tcp_config.tcp_conns_capacity; i++)
  {
    if (tcp_conn_table_src[i].valid &&
        tcp_conn_table_src[i].src_ip == src_ip &&
        tcp_conn_table_src[i].state == TCP_STATE_SYN_SENT)
    {
      count++;
    }
  }
  return count;
}

void filter(void)
{
  bool transmitted = false;
  bool returned = false;
  bool reprocess = true;
  while (reprocess)
  {
    while (!net_queue_empty_active(&rx_queue))
    {
      net_buff_desc_t buffer;
      int err = net_dequeue_active(&rx_queue, &buffer);
      assert(!err);

      void *pkt_vaddr = net_config.rx_data.vaddr + buffer.io_or_offset;
      ipv4_packet_t *ip_pkt = (ipv4_packet_t *)pkt_vaddr;
      tcphdr_t *tcp_hdr = (tcphdr_t *)(pkt_vaddr + transport_layer_offset(ip_pkt));

      /* First check if this is a SYN-ACK from a dst connection */
      tcp_conn_state_t *conn_dst = NULL;

      bool syn = tcp_hdr->syn;
      bool ack = tcp_hdr->ack;
      bool fin = tcp_hdr->fin;
      uint32_t seq = tcp_hdr->seq;
      uint32_t ack_seq = tcp_hdr->ack_seq;

      if (syn && ack)
      {

        for (int i = 0; i < tcp_config.tcp_conns_capacity; i++)
        {
          if (tcp_conn_table_dst[i].valid &&
              tcp_conn_table_dst[i].src_ip == ip_pkt->dst_ip &&
              tcp_conn_table_dst[i].src_port == tcp_hdr->dst_port &&
              tcp_conn_table_dst[i].dst_ip == ip_pkt->src_ip &&
              tcp_conn_table_dst[i].dst_port == tcp_hdr->src_port)
          {
            conn_dst = &tcp_conn_table_dst[i];
            break;
          }
        }

        if (conn_dst && (conn_dst->state == TCP_STATE_SYN_SENT || conn_dst->state == TCP_STATE_SYN_ACK_RECEIVED))
        {
          // SYN-ACK response
          conn_dst->state = TCP_STATE_SYN_ACK_RECEIVED;
          conn_dst->last_ack_seq = ack_seq;

          sddf_printf("TCP SYN-ACK seen: (%s:%u -> %s:%u) [State updated to SYN_ACK_RECEIVED]\n",
                      ipaddr_to_string(conn_dst->dst_ip, ip_addr_buf0), conn_dst->dst_port,
                      ipaddr_to_string(conn_dst->src_ip, ip_addr_buf1), conn_dst->src_port);

          /* Reset the checksum as it's recalculated in hardware */
          tcp_hdr->check = 0;

          err = fw_enqueue(&router_queue, net_fw_desc(buffer));
          assert(!err);
          transmitted = true;
          continue;
        }
        else
        {
          /* No established TCP connection, drop packet */
          sddf_printf("TCP SYN-ACK seen without connection, dropping packet!\n");
          err = net_enqueue_free(&rx_queue, buffer);
          assert(!err);
          returned = true;
          continue;
        }
      }

      bool default_action = false;
      uint8_t rule_id = 0;
      // COURTNEY: One thing to talk about later is this function searches through the other filter's instances,
      // and if there is a match it will return FILTER_ACT_ESTABLISHED. If this filter sees a tcp fin, we need to somehow
      // remove that connection from the other filter's instances. But we can talk about this later.
      // COURTNEY: Another thing is you may want to also look through THIS filter's instances, as if there is already an
      // established connection maybe you don't want to add to your TCP connection table
      fw_action_t action = fw_filter_find_action(&filter_state, ip_pkt->src_ip, tcp_hdr->src_port,
                                                 ip_pkt->dst_ip, tcp_hdr->dst_port, &rule_id);

      /* Perform the default action */
      if (action == FILTER_ACT_NONE)
      {
        default_action = true;
        action = filter_state.default_action;
        if (FW_DEBUG_OUTPUT)
        {
          sddf_printf("%sTCP filter found no match, performing default action %s: (ip %s, port %u) -> (ip %s, port %u)\n",
                      fw_frmt_str[filter_config.webserver.interface], fw_filter_action_str[action],
                      ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                      ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);
        }
      }

      /* Add an established connection in shared memory for corresponding filter */
      if (action == FILTER_ACT_CONNECT)
      {
        tcp_conn_state_t *conn_src = NULL;
        for (int i = 0; i < tcp_config.tcp_conns_capacity; i++)
        {
          if (tcp_conn_table_src[i].valid &&
              tcp_conn_table_src[i].src_ip == ip_pkt->src_ip &&
              tcp_conn_table_src[i].src_port == tcp_hdr->src_port &&
              tcp_conn_table_src[i].dst_ip == ip_pkt->dst_ip &&
              tcp_conn_table_src[i].dst_port == tcp_hdr->dst_port)
          {
            conn_src = &tcp_conn_table_src[i];
            break;
          }
        }

        // if (conn_src && (fin || tcp_hdr->rst))
        // {
        //   // COURTNEY: This is good, but in the future we may also want to remove from instances here? I realised
        //   // there is still some additional unhandled complexities with the instances table we need to talk about

        //   // Not sure if this in-built function works like this, keeping it just in case
        //   //   fw_filter_remove_instances(&filter_state,
        //   //                     conn_src->default_rule,
        //   //                     conn_src->rule_id);

        //   // These loops that Joji wrote seem more exact/precise
        //   for (int i = 0; i < filter_state.instances_capacity; i++)
        //   {
        //     fw_instance_t *inst = &filter_state.internal_instances[i];
        //     if (inst->valid &&
        //         inst->src_ip == conn_src->src_ip && inst->src_port == conn_src->src_port &&
        //         inst->dst_ip == conn_src->dst_ip && inst->dst_port == conn_src->dst_port)
        //     {
        //       inst->valid = false;
        //       break;
        //     }
        //   }

        //   for (int i = 0; i < filter_state.instances_capacity; i++)
        //   {
        //     fw_instance_t *inst = &filter_state.external_instances[i];
        //     if (inst->valid &&
        //         inst->src_ip == conn_src->src_ip && inst->src_port == conn_src->src_port &&
        //         inst->dst_ip == conn_src->dst_ip && inst->dst_port == conn_src->dst_port)
        //     {
        //       inst->valid = false;
        //       break;
        //     }
        //   }

        //   conn_src->valid = false; // Remove tracking entry
        //   sddf_printf("TCP connection closed for (ip %s, port %u) -> (ip %s, port %u)\n",
        //               ipaddr_to_string(conn_src->src_ip, ip_addr_buf0), conn_src->src_port,
        //               ipaddr_to_string(conn_src->dst_ip, ip_addr_buf1), conn_src->dst_port);
        // }

        // SYN
        if (syn && !ack && (conn_src == NULL || (conn_src != NULL && conn_src->state == TCP_STATE_SYN_SENT)))
        {
          int open_syns = count_open_syns(ip_pkt->src_ip);
          if (open_syns >= MAX_OPEN_SYNS_PER_IP)
          {
            // MAYBE: Reclaim a stale SYN_SENT entry?
            // for (int i = 0; i < tcp_config.tcp_conns_capacity; i++)
            // {
            //   tcp_conn_state_t *entry = &tcp_conn_table_src[i];
            //   if (entry->valid &&
            //       entry->src_ip == ip_pkt->src_ip &&
            //       entry->state == TCP_STATE_SYN_SENT)
            //   {
            //     sddf_printf("Dropping old SYN_SENT entry for %s:%u -> %s:%u\n",
            //                 ipaddr_to_string(entry->src_ip, ip_addr_buf0), entry->src_port,
            //                 ipaddr_to_string(entry->dst_ip, ip_addr_buf1), entry->dst_port);
            //     entry->valid = false;
            //     break;
            //   }
            // }

            sddf_printf("SYN flood protection triggered: dropping new SYN from %s:%u -> %s:%u (count = %d)\n",
                        ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                        ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port,
                        open_syns);

            err = net_enqueue_free(&rx_queue, buffer);
            assert(!err);
            returned = true;
            continue;
          }

          // New SYN
          // Only create a new connection entry if it doesn't already exist
          if (conn_src == NULL) {
            for (int i = 0; i < tcp_config.tcp_conns_capacity; i++)
            {
              if (!tcp_conn_table_src[i].valid)
              {
                tcp_conn_table_src[i].valid = true;
                tcp_conn_table_src[i].src_ip = ip_pkt->src_ip;
                tcp_conn_table_src[i].src_port = tcp_hdr->src_port;
                tcp_conn_table_src[i].dst_ip = ip_pkt->dst_ip;
                tcp_conn_table_src[i].dst_port = tcp_hdr->dst_port;
                tcp_conn_table_src[i].state = TCP_STATE_SYN_SENT;
                tcp_conn_table_src[i].last_seq = seq;
                sddf_printf("TCP SYN seen: (%s:%u -> %s:%u) [Tracking initiated]\n",
                            ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                            ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);
                break;
              }
            }
          }
        }
        // ACK
        else if (conn_src && ack && !syn && conn_src->state == TCP_STATE_SYN_ACK_RECEIVED)
        {
          // Final ACK
          sddf_printf("TCP ACK seen: (%s:%u -> %s:%u) [Handshake complete]\n",
                      ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                      ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);

          // COURTNEY: You could confirm it's final by looking at the sequence number as well
          conn_src->state = TCP_STATE_ESTABLISHED;
          conn_src->valid = false;
          // Now add instance
          fw_filter_err_t fw_err = fw_filter_add_instance(&filter_state, conn_src->src_ip, conn_src->src_port,
                                                          conn_src->dst_ip, conn_src->dst_port, default_action, rule_id);

          if (fw_err == FILTER_ERR_OKAY || fw_err == FILTER_ERR_DUPLICATE)
          {
            sddf_printf("%sTCP filter establishing connection via rule %u: (ip %s, port %u) -> (ip %s, port %u)\n",
                        fw_frmt_str[filter_config.webserver.interface], rule_id,
                        ipaddr_to_string(conn_src->src_ip, ip_addr_buf0), conn_src->src_port,
                        ipaddr_to_string(conn_src->dst_ip, ip_addr_buf1), conn_src->dst_port);
          }

          if (fw_err == FILTER_ERR_FULL)
          {
            sddf_printf("%sTCP FILTER LOG: could not establish connection for rule %u: (ip %s, port %u) -> (ip %s, port %u): %s\n",
                        fw_frmt_str[filter_config.webserver.interface],
                        rule_id, ipaddr_to_string(conn_src->src_ip, ip_addr_buf0), conn_src->src_port,
                        ipaddr_to_string(conn_src->dst_ip, ip_addr_buf1), conn_src->dst_port, fw_filter_err_str[fw_err]);
          }
        }
        else
        {
          sddf_printf("Attempted SYN retry or rogue ACK, dropping packet!\n");
          err = net_enqueue_free(&rx_queue, buffer);
          assert(!err);
          returned = true;
          continue;
        }
      }

      /* Transmit the packet to the routing component */
      if (action == FILTER_ACT_CONNECT || action == FILTER_ACT_ESTABLISHED || action == FILTER_ACT_ALLOW)
      {
        /* Reset the checksum as it's recalculated in hardware */
        tcp_hdr->check = 0;

        err = fw_enqueue(&router_queue, net_fw_desc(buffer));
        assert(!err);
        transmitted = true;

        if (FW_DEBUG_OUTPUT)
        {
          if (action == FILTER_ACT_ALLOW || action == FILTER_ACT_CONNECT)
          {
            sddf_printf("%sTCP filter transmitting via rule %u: (ip %s, port %u) -> (ip %s, port %u)\n",
                        fw_frmt_str[filter_config.webserver.interface], rule_id,
                        ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                        ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);
          }
          else if (action == FILTER_ACT_ESTABLISHED)
          {
            sddf_printf("%sTCP filter transmitting via external rule %u: (ip %s, port %u) -> (ip %s, port %u)\n",
                        fw_frmt_str[filter_config.webserver.interface], rule_id,
                        ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                        ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);
          }
        }
      }
      else if (action == FILTER_ACT_DROP)
      {
        /* Return the buffer to the rx virtualiser */
        err = net_enqueue_free(&rx_queue, buffer);
        assert(!err);
        returned = true;

        if (FW_DEBUG_OUTPUT)
        {
          sddf_printf("%sTCP filter dropping via rule %u: (ip %s, port %u) -> (ip %s, port %u)\n",
                      fw_frmt_str[filter_config.webserver.interface], rule_id,
                      ipaddr_to_string(ip_pkt->src_ip, ip_addr_buf0), tcp_hdr->src_port,
                      ipaddr_to_string(ip_pkt->dst_ip, ip_addr_buf1), tcp_hdr->dst_port);
        }
      }
    }

    net_request_signal_active(&rx_queue);
    reprocess = false;

    if (!net_queue_empty_active(&rx_queue))
    {
      net_cancel_signal_active(&rx_queue);
      reprocess = true;
    }
  }

  if (returned)
  {
    microkit_deferred_notify(net_config.rx.id);
  }

  if (transmitted)
  {
    microkit_notify(filter_config.router.ch);
  }
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
  switch (microkit_msginfo_get_label(msginfo))
  {
  case FW_SET_DEFAULT_ACTION:
  {
    fw_action_t action = seL4_GetMR(FILTER_ARG_ACTION);

    if (FW_DEBUG_OUTPUT)
    {
      sddf_printf("%sTCP filter changing default action from %u to %u\n",
                  fw_frmt_str[filter_config.webserver.interface], filter_state.default_action, action);
    }

    fw_filter_err_t err = fw_filter_update_default_action(&filter_state, action);
    assert(err == FILTER_ERR_OKAY);

    seL4_SetMR(FILTER_RET_ERR, err);
    return microkit_msginfo_new(0, 1);
  }
  case FW_ADD_RULE:
  {
    fw_action_t action = seL4_GetMR(FILTER_ARG_ACTION);
    uint32_t src_ip = seL4_GetMR(FILTER_ARG_SRC_IP);
    uint16_t src_port = seL4_GetMR(FILTER_ARG_SRC_PORT);
    uint32_t dst_ip = seL4_GetMR(FILTER_ARG_DST_IP);
    uint16_t dst_port = seL4_GetMR(FILTER_ARG_DST_PORT);
    uint8_t src_subnet = seL4_GetMR(FILTER_ARG_SRC_SUBNET);
    uint8_t dst_subnet = seL4_GetMR(FILTER_ARG_DST_SUBNET);
    bool src_port_any = seL4_GetMR(FILTER_ARG_SRC_ANY_PORT);
    bool dst_port_any = seL4_GetMR(FILTER_ARG_DST_ANY_PORT);
    uint16_t rule_id = 0;
    fw_filter_err_t err = fw_filter_add_rule(&filter_state, src_ip, src_port,
                                             dst_ip, dst_port, src_subnet, dst_subnet, src_port_any, dst_port_any, action, &rule_id);

    if (FW_DEBUG_OUTPUT)
    {
      sddf_printf("%sTCP filter create rule %u: (ip %s, mask %u, port %u, any_port %u) - (%s) -> (ip %s, mask %u, port %u, any_port %u): %s\n",
                  fw_frmt_str[filter_config.webserver.interface], rule_id,
                  ipaddr_to_string(src_ip, ip_addr_buf0), src_subnet, src_port, src_port_any, fw_filter_action_str[action],
                  ipaddr_to_string(dst_ip, ip_addr_buf1), dst_subnet, dst_port, dst_port_any, fw_filter_err_str[err]);
    }

    seL4_SetMR(FILTER_RET_ERR, err);
    seL4_SetMR(FILTER_RET_RULE_ID, rule_id);
    return microkit_msginfo_new(0, 2);
  }
  case FW_DEL_RULE:
  {
    uint16_t rule_id = seL4_GetMR(FILTER_ARG_RULE_ID);
    fw_filter_err_t err = fw_filter_remove_rule(&filter_state, rule_id);

    if (FW_DEBUG_OUTPUT)
    {
      sddf_printf("%sTCP remove rule id %u: %s\n",
                  fw_frmt_str[filter_config.webserver.interface], rule_id, fw_filter_err_str[err]);
    }

    seL4_SetMR(FILTER_RET_ERR, err);
    return microkit_msginfo_new(0, 1);
  }
  default:
    sddf_printf("%sTCP FILTER LOG: unknown request %lu on channel %u\n",
                fw_frmt_str[filter_config.webserver.interface],
                microkit_msginfo_get_label(msginfo), ch);
    break;
  }

  return microkit_msginfo_new(0, 0);
}

void notified(microkit_channel ch)
{
  if (ch == net_config.rx.id)
  {
    filter();
  }
  else
  {
    sddf_dprintf("%sTCP FILTER LOG: Received notification on unknown channel: %d!\n",
                 fw_frmt_str[filter_config.webserver.interface], ch);
  }
}

void init(void)
{
  assert(net_config_check_magic((void *)&net_config));

  net_queue_init(&rx_queue, net_config.rx.free_queue.vaddr, net_config.rx.active_queue.vaddr,
                 net_config.rx.num_buffers);

  fw_queue_init(&router_queue, filter_config.router.queue.vaddr, filter_config.router.capacity);

  fw_filter_state_init(&filter_state, filter_config.webserver.rules.vaddr, filter_config.webserver.rules_capacity,
                       filter_config.internal_instances.vaddr, filter_config.external_instances.vaddr, filter_config.instances_capacity,
                       FILTER_ACT_CONNECT);

  tcp_conn_table_src = (tcp_conn_state_t *)tcp_config.internal_tcp_conns.vaddr;
  tcp_conn_table_dst = (tcp_conn_state_t *)tcp_config.external_tcp_conns.vaddr;
}
