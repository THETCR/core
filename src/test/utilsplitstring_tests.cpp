// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/splitstring.h>

#include <string>
#include <vector>

#include <test/test_wispr.h>
#include <boost/test/unit_test.hpp>

// Comment out `#include <util/splitstring.h>` above and uncomment the lines below to validate
// the `Split` implementation against boost::split (the tests should yield the same result).
//
// #include <boost/algorithm/string/classification.hpp>
// #include <boost/algorithm/string/split.hpp>
//
// template<typename ContainerT>
// void Split(ContainerT& tokens, const std::string& str, const std::string& any_of_separator, bool merge_empty = false)
// {
//     boost::split(tokens, str, boost::is_any_of(any_of_separator), merge_empty ? boost::token_compress_on : boost::token_compress_off);
// }

BOOST_FIXTURE_TEST_SUITE(utilsplitstring_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(urlsplitstring_test)
    {
        {
            std::vector<std::string> result;
            Split(result, "", ",");
            std::vector<std::string> expected = {""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, "", ",", true);
            std::vector<std::string> expected = {""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",", ",");
            std::vector<std::string> expected = {"", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",", ",", true);
            std::vector<std::string> expected = {"", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,", ",");
            std::vector<std::string> expected = {"", "", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,", ",", true);
            std::vector<std::string> expected = {"", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,,", ",");
            std::vector<std::string> expected = {"", "", "", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,,", ",", true);
            std::vector<std::string> expected = {"", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, "Satoshi,Nakamoto", ",");
            std::vector<std::string> expected = {"Satoshi", "Nakamoto"};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, "Satoshi,Nakamoto", ",", true);
            std::vector<std::string> expected = {"Satoshi", "Nakamoto"};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,Satoshi,,,,,,Nakamoto,,", ",");
            std::vector<std::string> expected = {"", "", "Satoshi", "", "", "", "", "", "Nakamoto", "", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::vector<std::string> result;
            Split(result, ",,Satoshi,,,,,,Nakamoto,,", ",", true);
            std::vector<std::string> expected = {"", "Satoshi", "Nakamoto", ""};
            BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
        }

        {
            std::set<std::string> result;
            Split(result, "#reckless", "", false);
            BOOST_CHECK_EQUAL(result.count("#reckless"), 1);
        }

        {
            std::set<std::string> result;
            Split(result, "#reckless", "", true);
            BOOST_CHECK_EQUAL(result.count("#reckless"), 1);
        }

        {
            std::set<std::string> result;
            Split(result, "#reckless", ",#$", false);
            BOOST_CHECK_EQUAL(result.count(""), 1);
            BOOST_CHECK_EQUAL(result.count("reckless"), 1);
        }

        {
            std::set<std::string> result;
            Split(result, "#reckless|hodl bitcoin ", " |", true);
            BOOST_CHECK_EQUAL(result.count("#reckless"), 1);
            BOOST_CHECK_EQUAL(result.count("hodl"), 1);
            BOOST_CHECK_EQUAL(result.count("bitcoin"), 1);
            BOOST_CHECK_EQUAL(result.count(""), 1);
        }
    }

BOOST_AUTO_TEST_SUITE_END()