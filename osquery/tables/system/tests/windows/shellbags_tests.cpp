/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

// parseShellData is not exposed through a header; forward-declare it here.
void parseShellData(const std::string& shell_data,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid,
                    const std::string& source);

class ShellbagsTests : public testing::Test {
 protected:
  std::vector<std::string> build_shellbag;
  QueryData results;
  const std::string sid = "S-1-5-21-0000000000-0000000000-0000000000-1000";
  const std::string source = "usrclass.dat";
};

// Issue 1: shell_data.substr(4, 2) at the top of parseShellData is called
// unconditionally.  Any input shorter than 4 characters throws
// std::out_of_range.
TEST_F(ShellbagsTests, substr_sig_empty_input) {
  EXPECT_NO_THROW(parseShellData("", build_shellbag, results, sid, source));
}

TEST_F(ShellbagsTests, substr_sig_three_char_input) {
  EXPECT_NO_THROW(parseShellData("000", build_shellbag, results, sid, source));
}

// Issue 2: When sig (positions 4-5) equals "1F" and the data does not contain
// the "31535053" sentinel, the code reaches shell_data.substr(8, 2) without
// checking that the string is long enough.  A 6-character input (the minimum
// that can produce a 2-char sig) causes std::out_of_range because pos 8 >
// size 6.
TEST_F(ShellbagsTests, substr_root_folder_short_input) {
  // Positions 4-5 are '1','F' → sig == "1F"; string has no "31535053".
  const std::string shell_data = "00001F";
  EXPECT_NO_THROW(
      parseShellData(shell_data, build_shellbag, results, sid, source));
}

// Issue 3: When sig is "2F" (drive-letter branch), extension_sig is empty, and
// positions 6-7 are "80", the code extracts guid_little via
// shell_data.substr(8, 32).  For an 8-character input the extraction succeeds
// but returns an empty string.  That empty string is then passed to guidParse,
// which itself calls substr at offsets 8, 12, 16, and 20 and throws
// std::out_of_range.
TEST_F(ShellbagsTests, substr_guid_extraction_short_input) {
  // Positions 4-5 → "2F"; positions 6-7 → "80"; total length = 8.
  const std::string shell_data = "00002F80";
  EXPECT_NO_THROW(
      parseShellData(shell_data, build_shellbag, results, sid, source));
}

// Issue 4: When sig is "00" (variable shell-item branch) and the data does not
// contain "EEBBFE23", the code reaches shell_data.substr(12, 8) to check for
// an FTP variant.  A 6-character input (minimum to produce a 2-char sig)
// throws std::out_of_range because pos 12 > size 6.
TEST_F(ShellbagsTests, substr_variable_item_short_input) {
  // Positions 4-5 are '0','0' → sig == "00"; no "EEBBFE23" present.
  const std::string shell_data = "000000";
  EXPECT_NO_THROW(
      parseShellData(shell_data, build_shellbag, results, sid, source));
}

// Issue 5: In the catch-all else branch, if the data contains both "31535053"
// and "D5DFA323", the code assumes the data is long enough and calls
// shell_data.substr(226, 32) unconditionally.  A string that embeds both
// sentinels but is far shorter than 226 characters throws std::out_of_range.
TEST_F(ShellbagsTests, substr_property_guid_short_input) {
  // sig = "FF" (not matched by any earlier branch).
  // The string contains "31535053" and "D5DFA323" but is only 24 chars long.
  const std::string shell_data = "0000FF0031535053D5DFA323";
  EXPECT_NO_THROW(
      parseShellData(shell_data, build_shellbag, results, sid, source));
}

} // namespace tables
} // namespace osquery
