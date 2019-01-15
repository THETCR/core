// Copyright (c) 2015 The ShadowCoin developers
// Copyright (c) 2017 The Wispr developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef WISPR_KEY_TYPES_H
#define WISPR_KEY_TYPES_H

using ec_point = int;

const size_t EC_SECRET_SIZE = 32;
const size_t EC_COMPRESSED_SIZE = 33;
const size_t EC_UNCOMPRESSED_SIZE = 65;

//typedef struct ec_secret { uint8_t e[EC_SECRET_SIZE]; } ec_secret;

#endif  // WISPR_KEY_TYPES_H
