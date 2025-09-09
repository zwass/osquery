/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/system/system.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>


namespace osquery {
namespace tables {

QueryData genDNSResolvers(QueryContext& context) {
  QueryData results;

  const auto kMaxBufferAllocRetries = 3;
  const auto kWorkingBufferSize = 15000;

  DWORD buffSize = kWorkingBufferSize;
  auto alloc_attempts = 0;
  size_t alloc_result = 0;
  const auto addrFamily = AF_UNSPEC;
  const auto addrFlags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                         GAA_FLAG_SKIP_MULTICAST;
  std::unique_ptr<IP_ADAPTER_ADDRESSES> adapters(nullptr);

  // Buffer size can change between the query and malloc (if adapters are
  // added/removed), so we need to handle buffer overflow
  do {
    adapters.reset(static_cast<PIP_ADAPTER_ADDRESSES>(malloc(buffSize)));
    if (adapters == nullptr) {
      return results;
    }
    alloc_result = GetAdaptersAddresses(
        addrFamily, addrFlags, nullptr, adapters.get(), &buffSize);
    alloc_attempts++;
  } while (alloc_result == ERROR_BUFFER_OVERFLOW &&
           alloc_attempts < kMaxBufferAllocRetries);

  if (alloc_result != NO_ERROR) {
    return results;
  }

  int id = 0;
  const IP_ADAPTER_ADDRESSES* currAdapter = adapters.get();

  while (currAdapter != nullptr) {
    // Get DNS servers for this adapter
    const IP_ADAPTER_DNS_SERVER_ADDRESS* dnsServer =
        currAdapter->FirstDnsServerAddress;
    while (dnsServer != nullptr) {
      Row r;
      r["id"] = INTEGER(id++);
      r["type"] = "nameserver";

      // Convert IP address to string
      char addrBuff[INET6_ADDRSTRLEN] = {0};
      if (dnsServer->Address.lpSockaddr->sa_family == AF_INET) {
        inet_ntop(AF_INET,
                  &reinterpret_cast<sockaddr_in*>(
                      dnsServer->Address.lpSockaddr)
                      ->sin_addr,
                  addrBuff,
                  INET_ADDRSTRLEN);
        r["netmask"] = "32";
      } else if (dnsServer->Address.lpSockaddr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6,
                  &reinterpret_cast<sockaddr_in6*>(
                      dnsServer->Address.lpSockaddr)
                      ->sin6_addr,
                  addrBuff,
                  INET6_ADDRSTRLEN);
        r["netmask"] = "128";
      } else {
        dnsServer = dnsServer->Next;
        continue;
      }

      r["address"] = std::string(addrBuff);
      r["options"] = BIGINT(0);
      results.push_back(r);

      dnsServer = dnsServer->Next;
    }

    // Get DNS suffix search list for this adapter
    if (currAdapter->DnsSuffix != nullptr &&
        wcslen(currAdapter->DnsSuffix) > 0) {
      Row r;
      r["id"] = INTEGER(id++);
      r["type"] = "search";
      r["address"] = wstringToString(currAdapter->DnsSuffix);
      r["netmask"] = "";
      r["options"] = BIGINT(0);
      results.push_back(r);
    }

    currAdapter = currAdapter->Next;
  }

  return results;
}

} // namespace tables
} // namespace osquery
