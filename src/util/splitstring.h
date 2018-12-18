// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iterator>
#include <set>
#include <string>
#include <vector>
#include <type_traits>

#ifndef BITCOIN_UTIL_SPLITSTRING_H
#define BITCOIN_UTIL_SPLITSTRING_H

/**
 * Tokenizes a string by any of the given separators.
 * @param[in] tokens            The container (either an instance of std::vector<std::string>
 *                              or std::set<std::string>) to add tokenized string parts to.
 * @param[in] str               The string to tokenize.
 * @param[in] any_of_separator  A string with valid separators.
 * @param[in] merge_empty       Set to true to merge adjacent separators (empty tokens); otherwise false (default).
 */
template<typename ContainerT>
void Split(ContainerT& tokens, const std::string& str, const std::string& any_of_separator, bool merge_empty = false)
{
    static_assert(
            std::is_same<std::vector<std::string>, ContainerT>::value ||
            std::is_same<std::set<std::string>, ContainerT>::value,
            "`Split` has only been tested with template arguments of type `std::vector<std::string>` and `std::set<std::string>`");

    auto insertIt = std::inserter(tokens, tokens.end());
    if (str.empty()) {
        *insertIt = "";
        return;
    }

    const auto begin = str.cbegin();
    const auto end = str.cend();

    for (auto it = begin; it < end; ++it) {
        bool foundSeparator {false};
        auto start = it;

        for (; it < end; ++it) {
            foundSeparator = (any_of_separator.find(*it) != std::string::npos);
            if (foundSeparator) break;
        }

        if (it != begin && (!merge_empty || start != it)) {
            *insertIt = std::string(start, it);
        }

        if (foundSeparator) {
            if (it == begin) {
                *insertIt = "";
            }
            if (it == end - 1) {
                *insertIt = "";
            }
        }
    }
}

#endif // BITCOIN_UTIL_SPLITSTRING_H