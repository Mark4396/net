#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    // TODO 
    ip_hdr_t* tmp = buf->data;
    if(tmp->version == IP_VERSION_4 && tmp->hdr_len == 5 && swap16(tmp->total_len) <= ETHERNET_MTU){
        uint16_t checktmp = tmp->hdr_checksum;
        tmp->hdr_checksum = 0;
        if(checksum16((uint16_t*)tmp, 10) != checktmp) return;
        tmp->hdr_checksum = checktmp;
        if(memcmp(tmp->dest_ip, net_if_ip, NET_IP_LEN)) return;
        
        if(tmp->protocol == NET_PROTOCOL_ICMP){
            buf_remove_header(buf, 20);
           icmp_in(buf, tmp->src_ip);
        }
        else if(tmp->protocol == NET_PROTOCOL_UDP){
            buf_remove_header(buf, 20);
            udp_in(buf, tmp->src_ip);
        }
        else{
            icmp_unreachable(buf, tmp->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        }
    }
}

/**
 * @brief 处理一个要发送的分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TODO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t* tmp = (ip_hdr_t* )buf->data;
    tmp->version = IP_VERSION_4;
    tmp->hdr_len = 5;
    tmp->tos = 0;
    tmp->total_len = swap16(buf->len);
    tmp->id = swap16(id);
    tmp->flags_fragment = swap16((mf << 13) + offset);
    tmp->ttl = 64;
    tmp->protocol = protocol;
    tmp->hdr_checksum = 0;
    memcpy(tmp->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(tmp->dest_ip, ip, NET_IP_LEN);
     uint16_t checktmp = checksum16((uint16_t*)tmp,10);
    tmp->hdr_checksum = checktmp;
    arp_out(buf,ip,NET_PROTOCOL_IP);
}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - ip包头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - ip包头头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
static int id = 0;
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO 
    if(buf->len > 1480){
        int num  = (buf->len+1479)/1480, i=0;
        for(i; i < num-1; i++){
            buf_init(&txbuf,1480);
            memcpy(txbuf.data, buf->data+i*1480, 1480);
            ip_fragment_out(&txbuf,ip,protocol,id,i*1480/8, 1);
        }
            buf_init(&txbuf, buf->len-(num-1)*1480);
            memcpy(txbuf.data, buf->data+(num-1)*1480, buf->len-(num-1)*1480);
            ip_fragment_out(&txbuf,ip,protocol,id++,(num-1)*1480/8, 0);
    }
    else ip_fragment_out(buf, ip, protocol,id++,0,0);
}
