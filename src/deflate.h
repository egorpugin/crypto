#include <array>
#include <stdexcept>
#include <string>

struct deflater {
    template <auto MaxSize>
    struct encoded_table {
        static inline constexpr auto max_size = MaxSize;

        struct code_index_entry {
            int16_t word;
            int8_t length;
            bool valid;
        };
        struct code_remainder {
            uint8_t remainder;
            uint8_t bits_left;
            uint16_t index; // bit or with 0x8000 if it's the last one in sequence
        };

        // If value is greater than max_size, it's a remainder at index value minus max_size
        std::array<code_index_entry, 256> codes_index{};
        std::array<code_remainder, max_size> remainders{};
    };
    struct dynamic_coding {
        encoded_table<288> codes;
        encoded_table<31> distance_code;
    };

    static inline constexpr size_t outsz = 33000 * 2; // 32*1024*2+258;
    static inline constexpr auto reversed_bytes = []() {
        std::array<uint8_t, 256> v;
        for (int i = 0; i < 256; ++i) {
            v[i] = (i * 0x0202020202ULL & 0x010884422010ULL) % 0x3ff;
        }
        return v;
    }();

    using extracted_type = uint32_t;

    extracted_type data;
    const uint8_t *ptr;
    int bitpos;
    size_t bitsleft;
    std::string out;

    deflater() {
        out.reserve(outsz);
    }
    auto decode(const uint8_t *d, size_t len) {
        if (len > sizeof(extracted_type)) {
            ptr = d;
            auto sz = len - sizeof(extracted_type);
            bitsleft = sz * 8;
            len -= sz;
            d += sz;
            bitpos = 0;
            process();
        }
        if (len) {
            memcpy(&data, d, len);
            ptr = (const uint8_t *)d;
            bitpos = 0;
            process();
        }
    }
    auto getbits(int n) {
        if (n > 16) [[unlikely]] {
            throw std::runtime_error{"too big bit length"};
        }
        int byte = bitpos / 8;
        // currently if we are on the page boundary, this can segv
        auto u = *(extracted_type *)(ptr + byte);
        u >>= bitpos % 8;
        bitpos += n;
        u &= (1 << n) - 1;
        return u;
    }
    void process() {
        static constexpr int distance_offsets[]{1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                                193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    more:
        auto header = getbits(3);
        switch (header >> 1) {
        case 0: {
            bitpos = (bitpos + 8 - 1) / 8 * 8;
            auto len = getbits(16);
            auto nlen = getbits(16);
            if ((~len & 0xffff) != nlen) {
                throw std::runtime_error("Corrupted data, inverted length of literal block is mismatching");
            }
            out.append((const char *)data + bitpos / 8, len);
            bitpos += len * 8;
            break;
        }
        case 0b01: {
            static constexpr auto code_index = []() {
                struct code_entry {
                    int8_t length;
                    int16_t code;
                };
                std::array<code_entry, 256> ci;
                for (int i = 0; i < 256; ++i) {
                    uint8_t reversed = reversed_bytes[i];
                    if (reversed < 0b00000010) {
                        ci[i] = {7, 256};
                    } else if (reversed < 0b00110000) {
                        ci[i] = {7, int16_t((reversed >> 1) - 1 + 257)};
                    } else if (reversed < 0b11000000) {
                        ci[i] = {8, int16_t(reversed - 0b00110000)};
                    } else if (reversed < 0b11001000) {
                        ci[i] = {8, int16_t(reversed - 0b11000000 + 280)};
                    } else {
                        ci[i] = {8, int16_t(reversed - 0b11001000 + 144)};
                    }
                }
                return ci;
            }();
            while (1) {
                auto c = code_index[getbits(8)];
                bitpos += c.length - 8;
                auto word = c.code;
                if (word < 256) {
                    out += (uint8_t)(word < 144 ? word : (((word - 144)) << 1) + 144 + getbits(1));
                } else if (word == 256) [[unlikely]] {
                    break;
                } else {
                    int length = word - 254;
                    if (length > 10) {
                        if (length == 31) {
                            length = 258;
                        } else {
                            int next_bits = (length++ - 7) >> 2;
                            auto additional_bits = getbits(next_bits);
                            // this is a generalization of the size table at 3.2.5
                            length = ((((length & 0x3) << next_bits) | additional_bits)) + ((1 << (length >> 2)) + 3);
                        }
                    }
                    static constexpr auto length_dictionary = []() {
                        std::array<uint8_t, 32> d;
                        for (int i = 0; i < 32; ++i) {
                            d[i] = (reversed_bytes[i] >> 3) + 1;
                        }
                        return d;
                    }();
                    int distance = length_dictionary[getbits(5)];
                    if (distance > 4) {
                        distance = distance_offsets[distance - 1] + getbits((distance - 3) >> 1);
                    }
                    append(length, distance);
                }
            }
            break;
        }
        [[likely]]
        case 0b10: {
            auto hliteral = getbits(5);
            if (hliteral > 29) [[unlikely]] {
                throw std::runtime_error{"bad length"};
            }
            auto hdist = getbits(5) + 1;
            if (hdist > 31) [[unlikely]] {
                throw std::runtime_error{"Impossible number of distance codes"};
            }
            auto hcode_length = getbits(4) + 4;
            if (hcode_length > 19) [[unlikely]] {
                throw std::runtime_error{"Invalid distance code count"};
            }
            static constexpr std::array<uint8_t, 19> codeCodingReorder{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            std::array<uint8_t, codeCodingReorder.size()> codeCodingLengths{};
            for (int i = 0; i < hcode_length; i++) {
                codeCodingLengths[codeCodingReorder[i]] = getbits(3);
            }
            // Generate Huffman codes for lengths
            std::array<uint8_t, 256> codeCodingLookup{};
            for (int size = 1, nextCodeCoding = 0; size <= 8; ++size) {
                for (int i = 0; i < codeCodingReorder.size(); ++i) {
                    if (codeCodingLengths[i] == size) {
                        for (int code = nextCodeCoding << (8 - size), end = (nextCodeCoding + 1) << (8 - size); code < end; ++code) {
                            codeCodingLookup[reversed_bytes[code]] = i;
                        }
                        nextCodeCoding++;
                    }
                }
                nextCodeCoding <<= 1;
            }
            //
            dynamic_coding dc;
            auto read_table = [&](auto &t, int real_size) {
                struct code_entry {
                    uint8_t start;
                    uint8_t ending;
                    uint8_t length;
                };
                struct unindexed_entry {
                    int quantity;
                    int startIndex;
                    int filled;
                };
                std::array<code_entry, t.max_size> codes{};
                std::array<int, 17> quantities{};
                for (int i = 0; i < real_size;) {
                    auto length = codeCodingLookup[getbits(8)];
                    bitpos += codeCodingLengths[length] - 8;
                    if (length < 16) {
                        codes[i++].length = length;
                        quantities[length]++;
                    } else if (length == 16) {
                        if (i == 0) [[unlikely]] {
                            throw std::runtime_error{"Invalid lookback position"};
                        }
                        int copy = getbits(2) + 3;
                        for (int j = i; j < i + copy; j++) {
                            codes[j].length = codes[i - 1].length;
                        }
                        quantities[codes[i - 1].length] += copy;
                        i += copy;
                    } else if (length > 16) {
                        int zeroCount = 0;
                        if (length == 17) {
                            zeroCount = getbits(3) + 3;
                        } else {
                            zeroCount = getbits(7) + 11;
                        };
                        for (int j = i; j < i + zeroCount; j++) {
                            codes[j].length = 0;
                        }
                        i += zeroCount;
                    }
                }
                // Generate the codes
                std::array<unindexed_entry, 256> unindexedEntries{};
                for (int size = 1, nextCode = 0; size <= 16; size++) {
                    if (quantities[size] > 0) {
                        for (int i = 0; i <= real_size; i++) {
                            if (codes[i].length == size) {
                                if (nextCode >= (1 << size)) [[unlikely]] {
                                    throw std::runtime_error{"Bad Huffman encoding, run out of Huffman codes"};
                                }
                                uint8_t firstPart = nextCode;
                                if (size <= 8) [[likely]] {
                                    codes[i].start = reversed_bytes[firstPart];
                                    for (int code = codes[i].start >> (8 - size); code < t.codes_index.size(); code += (1 << size)) {
                                        t.codes_index[code].word = i;
                                        t.codes_index[code].length = size;
                                        t.codes_index[code].valid = true;
                                    }
                                } else {
                                    auto start = reversed_bytes[(uint8_t)(nextCode >> (size - 8))];
                                    codes[i].start = start;
                                    t.codes_index[start].valid = true;
                                    unindexedEntries[start].quantity++;
                                    codes[i].ending = reversed_bytes[(uint8_t)nextCode] >> (16 - size);
                                }
                                nextCode++;
                            }
                        }
                    }
                    nextCode <<= 1;
                }
                // Calculate ranges of the longer parts
                for (int currentStartIndex{}; auto &&entry : unindexedEntries) {
                    entry.startIndex = currentStartIndex;
                    currentStartIndex += entry.quantity;
                }
                // Index the longer parts
                for (int i = 0; i < codes.size(); i++) {
                    auto &code = codes[i];
                    if (code.length > 8) {
                        auto &unindexedEntry = unindexedEntries[code.start];
                        auto &remainder = t.remainders[unindexedEntry.startIndex + unindexedEntry.filled];
                        t.codes_index[code.start].word = t.max_size + unindexedEntry.startIndex;
                        unindexedEntry.filled++;
                        remainder.remainder = code.ending; // The upper bits are cut
                        remainder.bits_left = code.length - 8;
                        remainder.index = i;
                        if (unindexedEntry.filled == unindexedEntry.quantity) {
                            remainder.index |= 0x8000;
                        }
                    }
                }
            };
            read_table(dc.codes, hliteral + 257);
            read_table(dc.distance_code, hdist);
            auto read_word = [&](auto &t) {
                auto &entry = t.codes_index[getbits(8)];
                auto word = entry.word;
                if (word >= t.max_size) {
                    bitpos += 8 - 8;
                } else if (!entry.valid) [[unlikely]] {
                    throw std::runtime_error{"Unknown Huffman code (not even first 8 bits)"};
                } else {
                    bitpos += entry.length - 8;
                }
                static constexpr std::array<uint8_t, 9> end_masks = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
                if (word >= t.max_size) {
                    auto b = getbits(8);
                    for (int i = word - t.max_size; i < t.max_size * 2; i++) {
                        if ((b & end_masks[t.remainders[i].bits_left]) == t.remainders[i].remainder) {
                            word = t.remainders[i].index & 0x7fff;
                            bitpos += t.remainders[i].bits_left - 8;
                            return word;
                        }
                        if (t.remainders[i].index & 0x8000) [[unlikely]] {
                            throw std::runtime_error{"Unknown Huffman code (ending bits don't fit)"};
                        }
                    }
                    throw std::runtime_error{"Unknown Huffman code (bad prefix)"};
                }
                return word;
            };
            while (1) {
                auto word = read_word(dc.codes);
                if (word < 256) {
                    out += (uint8_t)word;
                } else if (word == 256) [[unlikely]] {
                    break;
                } else {
                    int length = word - 254;
                    if (length > 10) {
                        if (length == 31) {
                            length = 258;
                        } else {
                            int next_bits = (length++ - 7) >> 2;
                            auto additional_bits = getbits(next_bits);
                            // this is a generalization of the size table at 3.2.5
                            length = ((((length & 0x3) << next_bits) | additional_bits)) + ((1 << (length >> 2)) + 3);
                        }
                    }
                    int distance = read_word(dc.distance_code) + 1;
                    if (distance > 4) {
                        distance = distance_offsets[distance - 1] + getbits((distance - 3) >> 1);
                    }
                    append(length, distance);
                }
            }
            break;
        }
        default:
            throw std::runtime_error{"bad type"};
        }
        if (!(header & 1)) {
            goto more;
        }
    }
    void append(int length, int distance) {
        while (length > 0) {
            auto sz = out.size();
            auto tocopy = std::min<size_t>(distance, length);
            out.append(out.data() + sz - distance, tocopy);
            length -= tocopy;
            distance += tocopy;
        }
    }
};
