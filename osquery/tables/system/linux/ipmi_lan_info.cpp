/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

// Ensure __user is defined to nothing when compiling from userspace so that
// the Linux UAPI header can be included without errors.
#ifndef __user
#define __user
#endif
#include <linux/ipmi.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

namespace {

// IPMI NetFn constants
const uint8_t kIpmiNetFnApp = 0x06;
const uint8_t kIpmiNetFnTransport = 0x0C;

// IPMI command codes
const uint8_t kIpmiCmdGetChannelInfo = 0x42;
const uint8_t kIpmiCmdGetLanConfig = 0x02;

// Channel medium type for 802.3 LAN
const uint8_t kIpmiChannelMediumLan = 4;

// LAN configuration parameter selectors (IPMI spec Table 23-4)
const uint8_t kIpmiLanParamIpSrc = 4;
const uint8_t kIpmiLanParamIpAddr = 3;
const uint8_t kIpmiLanParamSubnet = 6;
const uint8_t kIpmiLanParamMac = 5;
const uint8_t kIpmiLanParamGateway = 12;
const uint8_t kIpmiLanParamVlanId = 20;

// ipmi response timeout.
const int kIpmiTimeoutUsecs = 250000; // 250 ms

// Candidate device paths for the OpenIPMI kernel interface
const std::vector<std::string> kIpmiDevicePaths = {
    "/dev/ipmi0",
    "/dev/ipmi/0",
    "/dev/ipmidev/0",
};

int openIpmiDevice() {
  for (const auto& path : kIpmiDevicePaths) {
    int fd = open(path.c_str(), O_RDWR);
    if (fd >= 0) {
      return fd;
    }
  }
  return -1;
}

// Send an IPMI command via the system interface and wait for a response.
// Returns the response payload (completion code stripped) or an empty vector
// on failure or a non-zero completion code.
std::vector<uint8_t> ipmiSendRecv(int fd,
                                   uint8_t netfn,
                                   uint8_t cmd,
                                   const std::vector<uint8_t>& req_data,
                                   long msgid) {
  struct ipmi_system_interface_addr smi_addr = {};
  smi_addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
  smi_addr.channel = IPMI_BMC_CHANNEL;
  smi_addr.lun = 0;

  struct ipmi_req req = {};
  req.addr = reinterpret_cast<unsigned char*>(&smi_addr);
  req.addr_len = sizeof(smi_addr);
  req.msgid = msgid;
  req.msg.netfn = netfn;
  req.msg.cmd = cmd;
  req.msg.data = const_cast<unsigned char*>(req_data.data());
  req.msg.data_len = static_cast<uint16_t>(req_data.size());

  if (ioctl(fd, IPMICTL_SEND_COMMAND, &req) < 0) {
    return {};
  }

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  struct timeval tv = {0, kIpmiTimeoutUsecs};
  if (select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) {
    return {};
  }

  uint8_t recv_buf[128] = {};
  struct ipmi_addr recv_addr = {};
  struct ipmi_recv recv = {};
  recv.addr = reinterpret_cast<unsigned char*>(&recv_addr);
  recv.addr_len = sizeof(recv_addr);
  recv.msg.data = recv_buf;
  recv.msg.data_len = sizeof(recv_buf);

  if (ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv) < 0) {
    return {};
  }

  // recv_buf[0] is the completion code; 0x00 means success.
  if (recv.msg.data_len < 1 || recv_buf[0] != 0x00) {
    return {};
  }

  return std::vector<uint8_t>(recv_buf + 1,
                               recv_buf + recv.msg.data_len);
}

std::string formatIPv4(const uint8_t* b) {
  char buf[16];
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return buf;
}

std::string formatMAC(const uint8_t* b) {
  char buf[18];
  snprintf(buf,
           sizeof(buf),
           "%02x:%02x:%02x:%02x:%02x:%02x",
           b[0], b[1], b[2], b[3], b[4], b[5]);
  return buf;
}

std::string ipSrcToString(uint8_t src) {
  switch (src & 0x0F) {
  case 0:
    return "unspecified";
  case 1:
    return "static";
  case 2:
    return "dhcp";
  case 3:
    return "bios";
  case 4:
    return "other";
  default:
    return "unknown";
  }
}

} // namespace

QueryData getIpmiLanInfo(QueryContext& context) {
  QueryData results;

  int fd = openIpmiDevice();
  if (fd < 0) {
    VLOG(1) << "No IPMI device found; skipping ipmi_info";
    return results;
  }

  long msgid = 1;

  // IPMI channels 1-11 may be LAN channels. Channel 0 is the primary IPMB
  // and channel 15 is the system interface; neither carries LAN config.
  for (uint8_t channel = 1; channel <= 11; ++channel) {
    auto info = ipmiSendRecv(
        fd, kIpmiNetFnApp, kIpmiCmdGetChannelInfo, {channel}, msgid++);

    // Response layout (after completion code):
    //   [0] actual channel number
    //   [1] medium type (bits 6:0)
    //   [2] protocol type
    //   ...
    if (info.size() < 2) {
      continue;
    }

    const uint8_t medium_type = info[1] & 0x7F;
    if (medium_type != kIpmiChannelMediumLan) {
      continue;
    }

    // Found a LAN channel — query its configuration parameters.
    // Each Get LAN Config response is: [parameter_revision, parameter_data...]
    Row r;
    r["channel"] = INTEGER(channel);

    auto ip_src = ipmiSendRecv(fd,
                               kIpmiNetFnTransport,
                               kIpmiCmdGetLanConfig,
                               {channel, kIpmiLanParamIpSrc, 0, 0},
                               msgid++);
    r["ip_address_source"] = (ip_src.size() >= 2)
                                  ? ipSrcToString(ip_src[1])
                                  : "";

    auto ip_addr = ipmiSendRecv(fd,
                                kIpmiNetFnTransport,
                                kIpmiCmdGetLanConfig,
                                {channel, kIpmiLanParamIpAddr, 0, 0},
                                msgid++);
    r["ip_address"] = (ip_addr.size() >= 5) ? formatIPv4(ip_addr.data() + 1)
                                             : "";

    auto subnet = ipmiSendRecv(fd,
                               kIpmiNetFnTransport,
                               kIpmiCmdGetLanConfig,
                               {channel, kIpmiLanParamSubnet, 0, 0},
                               msgid++);
    r["subnet_mask"] =
        (subnet.size() >= 5) ? formatIPv4(subnet.data() + 1) : "";

    auto mac = ipmiSendRecv(fd,
                            kIpmiNetFnTransport,
                            kIpmiCmdGetLanConfig,
                            {channel, kIpmiLanParamMac, 0, 0},
                            msgid++);
    r["mac_address"] = (mac.size() >= 7) ? formatMAC(mac.data() + 1) : "";

    auto gw = ipmiSendRecv(fd,
                           kIpmiNetFnTransport,
                           kIpmiCmdGetLanConfig,
                           {channel, kIpmiLanParamGateway, 0, 0},
                           msgid++);
    r["gateway"] = (gw.size() >= 5) ? formatIPv4(gw.data() + 1) : "";

    // VLAN ID (param 20): [param_rev, vlan_id_low, vlan_id_high]
    // Bits 11:0 of the two data bytes hold the VLAN ID; bit 15 is the enable
    // flag. Report 0 when VLAN tagging is disabled or the parameter is absent.
    auto vlan = ipmiSendRecv(fd,
                             kIpmiNetFnTransport,
                             kIpmiCmdGetLanConfig,
                             {channel, kIpmiLanParamVlanId, 0, 0},
                             msgid++);
    if (vlan.size() >= 3 && (vlan[2] & 0x80)) {
      const int vlan_id = ((vlan[2] & 0x0F) << 8) | vlan[1];
      r["vlan_id"] = INTEGER(vlan_id);
    } else {
      r["vlan_id"] = INTEGER(0);
    }

    // Skip inactive virtual interfaces that have no real hardware behind them.
    // A missing or all-zero MAC is the reliable signal: if the BMC has no MAC
    // it has no physical presence on that channel.
    const auto& mac_val = r["mac_address"];
    if (mac_val.empty() || mac_val == "00:00:00:00:00:00") {
      continue;
    }

    results.push_back(r);
  }

  close(fd);
  return results;
}

} // namespace tables
} // namespace osquery
