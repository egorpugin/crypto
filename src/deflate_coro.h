#include <array>
#include <coroutine>
#include <stdexcept>
#include <string>

//#include <iostream>

struct deflater_coro {
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

    template <typename T>
    struct resumable {
        struct promise_type_base {
            std::coroutine_handle<> parent;

            /*void *operator new(std::size_t n) noexcept {
                if (auto mem = std::malloc(n)) {
                    //std::cerr << std::format("alloc {:4} {}\n", n, mem);
                    return mem;
                }
                return nullptr;
            }
            void operator delete(void *p) noexcept {
                //std::cerr << std::format("free       {}\n", p);
                std::free(p);
            }*/
            auto get_return_object(this auto &&self) {
                return resumable{std::coroutine_handle<std::decay_t<decltype(self)>>::from_promise(self)};
            }
            auto initial_suspend() noexcept {return std::suspend_always{};}
            auto final_suspend() noexcept {
                struct awaitable {
                    promise_type_base &self;

                    bool await_ready() noexcept {
                        return !self.parent;
                    }
                    auto await_suspend(std::coroutine_handle<>) noexcept {
                        return self.parent ? self.parent : std::noop_coroutine();
                    }
                    void await_resume() noexcept {}
                };
                return awaitable{*this};
            }
            auto unhandled_exception() { throw; }
            auto await_transform(auto &&other) {
                return std::move(other);
            }
            template <typename U>
            auto await_transform(resumable<U> &&u) {
                struct awaitable {
                    typename resumable<U>::promise_type &p;

                    bool await_ready() noexcept {
                        return std::coroutine_handle<typename resumable<U>::promise_type>::from_promise(p).done();
                    }
                    auto await_suspend(std::coroutine_handle<> h) noexcept {
                        p.parent = h;
                        return std::coroutine_handle<typename resumable<U>::promise_type>::from_promise(p);
                    }
                    U await_resume() noexcept {
                        auto v = p.value;
                        std::coroutine_handle<typename resumable<U>::promise_type>::from_promise(p).destroy();
                        return v;
                    }
                };
                return awaitable{u.h.promise()};
            }
            auto await_transform(resumable<void> &&u) {
                struct awaitable {
                    typename resumable<void>::promise_type &p;

                    bool await_ready() noexcept {
                        return std::coroutine_handle<typename resumable<void>::promise_type>::from_promise(p).done();
                    }
                    auto await_suspend(std::coroutine_handle<> h) noexcept {
                        p.parent = h;
                        return std::coroutine_handle<typename resumable<void>::promise_type>::from_promise(p);
                    }
                    void await_resume() noexcept {
                        std::coroutine_handle<typename resumable<void>::promise_type>::from_promise(p).destroy();
                    }
                };
                return awaitable{u.h.promise()};
            }
        };
        struct promise_type_void : promise_type_base {
            auto return_void() {}
        };
        struct promise_type_value : promise_type_base {
            T value;
            void return_value(T v) {value = v;}
        };
        using promise_type = std::conditional_t<std::is_same_v<T,void>,promise_type_void,promise_type_value>;

        std::coroutine_handle<promise_type> h;
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

    //extracted_type data;
    const uint8_t *ptr;
    int bitpos;
    int bitsleft;
    std::string out;
    std::coroutine_handle<> h;

    deflater_coro() {
        out.reserve(outsz);
    }
    auto decode(const uint8_t *d, size_t len) {
        if (!h) {
            ptr = d;
            bitpos = 0;
            bitsleft = len * 8;
            process().h();
        } else {
            auto minusbytes = (bitsleft + 8 - 1) / 8;
            ptr = d - minusbytes;
            bitpos = minusbytes * 8 - bitsleft;
            bitsleft = (len + minusbytes) * 8;
            h();
        }
    }
    auto getbits(int n, bool peek = false) {
        if (n > 16) [[unlikely]] {
            throw std::runtime_error{"too big bit length"};
        }
        struct awaitable {
            deflater_coro &d;
            int n;
            bool peek;

            bool await_ready() noexcept {
                return n <= d.bitsleft || (peek && d.bitsleft > 0);
            }
            bool await_suspend(std::coroutine_handle<> h) noexcept {
                d.h = h;
                return true;
            }
            extracted_type await_resume() noexcept {
                return d.getbits_raw(n);
            }
        };
        return awaitable{*this, n, peek};
    }
    extracted_type getbits_raw(int n) {
        int byte = bitpos / 8;
        // currently if we are on the page boundary, this can segv
        auto u = *(extracted_type *)(ptr + byte);
        u >>= bitpos % 8;
        inc(n);
        u &= (1 << n) - 1;
        return u;
    }
    void inc(int n) {
        bitpos += n;
        bitsleft -= n;
    }
    resumable<void> process() {
        static constexpr int distance_offsets[]{1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                                193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
        while (1) {
        auto header = co_await getbits(3);
        switch (header >> 1) {
        case 0: {
            inc((bitpos + 8 - 1) / 8 * 8 - bitpos);
            auto len = co_await getbits(16);
            auto nlen = co_await getbits(16);
            if ((~len & 0xffff) != nlen) {
                throw std::runtime_error{"Corrupted data, inverted length of literal block is mismatching"};
            }
            while (len) {
                if (bitsleft == 0) {
                    co_await getbits(8);
                    inc(-8);
                }
                auto to_copy = std::min<size_t>(bitsleft / 8, len);
                out.append((const char *)ptr + bitpos / 8, to_copy);
                inc(to_copy * 8);
                len -= to_copy;
            }
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
                auto b = co_await getbits(8, true);
                auto c = code_index[b];
                inc(c.length - 8);
                auto word = c.code;
                if (word < 256) {
                    out += (uint8_t)(word < 144 ? word : (((word - 144)) << 1) + 144 + co_await getbits(1));
                } else if (word == 256) [[unlikely]] {
                    break;
                } else {
                    int length = word - 254;
                    if (length > 10) {
                        if (length == 31) {
                            length = 258;
                        } else {
                            int next_bits = (length++ - 7) >> 2;
                            auto additional_bits = co_await getbits(next_bits);
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
                    auto b = co_await getbits(5);
                    int distance = length_dictionary[b];
                    if (distance > 4) {
                        distance = distance_offsets[distance - 1] + co_await getbits((distance - 3) >> 1);
                    }
                    append(length, distance);
                }
            }
            break;
        }
        [[likely]]
        case 0b10: {
            auto hliteral = co_await getbits(5);
            if (hliteral > 29) [[unlikely]] {
                throw std::runtime_error{"bad length"};
            }
            auto hdist = co_await getbits(5) + 1;
            if (hdist > 31) [[unlikely]] {
                throw std::runtime_error{"Impossible number of distance codes"};
            }
            auto hcode_length = co_await getbits(4) + 4;
            if (hcode_length > 19) [[unlikely]] {
                throw std::runtime_error{"Invalid distance code count"};
            }
            static constexpr std::array<uint8_t, 19> codeCodingReorder{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            std::array<uint8_t, codeCodingReorder.size()> codeCodingLengths{};
            for (int i = 0; i < hcode_length; i++) {
                codeCodingLengths[codeCodingReorder[i]] = co_await getbits(3);
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
            auto read_table = [&](auto &t, int real_size) -> resumable<void> {
                struct code_entry {
                    uint8_t start;
                    uint8_t ending;
                    uint8_t length;
                };
                struct unindexed_entry {
                    int quantity;
                    int start_index;
                    int filled;
                };
                std::array<code_entry, t.max_size> codes{};
                std::array<int, 17> quantities{};
                for (int i = 0; i < real_size;) {
                    auto b = co_await getbits(8, true);
                    auto length = codeCodingLookup[b];
                    inc(codeCodingLengths[length] - 8);
                    if (length < 16) {
                        codes[i++].length = length;
                        quantities[length]++;
                    } else if (length == 16) {
                        if (i == 0) [[unlikely]] {
                            throw std::runtime_error{"Invalid lookback position"};
                        }
                        int copy = co_await getbits(2) + 3;
                        for (int j = i; j < i + copy; j++) {
                            codes[j].length = codes[i - 1].length;
                        }
                        quantities[codes[i - 1].length] += copy;
                        i += copy;
                    } else if (length > 16) {
                        int zeroCount = 0;
                        if (length == 17) {
                            zeroCount = co_await getbits(3) + 3;
                        } else {
                            zeroCount = co_await getbits(7) + 11;
                        };
                        for (int j = i; j < i + zeroCount; j++) {
                            codes[j].length = 0;
                        }
                        i += zeroCount;
                    }
                }
                // Generate the codes
                std::array<unindexed_entry, 256> unindexed_entries{};
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
                                    unindexed_entries[start].quantity++;
                                    codes[i].ending = reversed_bytes[(uint8_t)nextCode] >> (16 - size);
                                }
                                nextCode++;
                            }
                        }
                    }
                    nextCode <<= 1;
                }
                // Calculate ranges of the longer parts
                for (int i{}; auto &&entry : unindexed_entries) {
                    entry.start_index = i;
                    i += entry.quantity;
                }
                // Index the longer parts
                for (int i = 0; i < codes.size(); i++) {
                    auto &code = codes[i];
                    if (code.length > 8) {
                        auto &ue = unindexed_entries[code.start];
                        auto &remainder = t.remainders[ue.start_index + ue.filled];
                        t.codes_index[code.start].word = t.max_size + ue.start_index;
                        ue.filled++;
                        remainder.remainder = code.ending; // The upper bits are cut
                        remainder.bits_left = code.length - 8;
                        remainder.index = i;
                        if (ue.filled == ue.quantity) {
                            remainder.index |= 0x8000;
                        }
                    }
                }
            };
            co_await read_table(dc.codes, hliteral + 257);
            co_await read_table(dc.distance_code, hdist);
            auto read_word = [&](auto &t) -> resumable<uint16_t> {
                auto b = co_await getbits(8, true);
                auto &entry = t.codes_index[b];
                auto word = entry.word;
                if (word >= t.max_size) {
                    inc(8 - 8);
                } else if (!entry.valid) [[unlikely]] {
                    throw std::runtime_error{"Unknown Huffman code (not even first 8 bits)"};
                } else {
                    inc(entry.length - 8);
                }
                static constexpr std::array<uint8_t, 9> end_masks = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
                if (word >= t.max_size) {
                    auto b = co_await getbits(8, true);
                    for (int i = word - t.max_size; i < t.max_size * 2; i++) {
                        if ((b & end_masks[t.remainders[i].bits_left]) == t.remainders[i].remainder) {
                            word = t.remainders[i].index & 0x7fff;
                            inc(t.remainders[i].bits_left - 8);
                            co_return word;
                        }
                        if (t.remainders[i].index & 0x8000) [[unlikely]] {
                            throw std::runtime_error{"Unknown Huffman code (ending bits don't fit)"};
                        }
                    }
                    throw std::runtime_error{"Unknown Huffman code (bad prefix)"};
                }
                co_return word;
            };
            while (1) {
                auto word = co_await read_word(dc.codes);
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
                            auto additional_bits = co_await getbits(next_bits);
                            // this is a generalization of the size table at 3.2.5
                            length = ((((length & 0x3) << next_bits) | additional_bits)) + ((1 << (length >> 2)) + 3);
                        }
                    }
                    int distance = co_await read_word(dc.distance_code) + 1;
                    if (distance > 4) {
                        distance = distance_offsets[distance - 1] + co_await getbits((distance - 3) >> 1);
                    }
                    append(length, distance);
                }
            }
            break;
        }
        default:
            throw std::runtime_error{"bad type"};
        }
        if (header & 1) {
            break;
        }
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
