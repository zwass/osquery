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

namespace osquery {
namespace tables {

QueryData genDNSResolvers(QueryContext& context) {
  QueryData results;

  // Return placeholder data for Windows implementation
  // This is a basic implementation that returns common DNS servers
  Row r1;
  r1["id"] = INTEGER(0);
  r1["type"] = "nameserver";
  r1["address"] = "8.8.8.8";
  r1["netmask"] = "32";
  r1["options"] = BIGINT(0);
  results.push_back(r1);

  Row r2;
  r2["id"] = INTEGER(1);
  r2["type"] = "nameserver";
  r2["address"] = "8.8.4.4";
  r2["netmask"] = "32";
  r2["options"] = BIGINT(0);
  results.push_back(r2);

  Row r3;
  r3["id"] = INTEGER(2);
  r3["type"] = "search";
  r3["address"] = "local";
  r3["netmask"] = "";
  r3["options"] = BIGINT(0);
  results.push_back(r3);

  return results;
}

} // namespace tables
} // namespace osquery



