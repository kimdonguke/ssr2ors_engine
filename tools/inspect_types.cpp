/* enumerate RTCM3 message types present in a stream                       */
#include "rtcm_decode.hpp"
#include <cstdio>
#include <cstdint>
#include <map>

int main(int argc, char* argv[])
{
    if (argc < 2) { std::fprintf(stderr, "usage: %s <file>\n", argv[0]); return 1; }
    std::FILE* fp = std::fopen(argv[1], "rb");
    if (!fp) return 1;

    std::map<int, long> count;
    long total = 0, bad_crc = 0;

    /* mini frame sync (same as RtcmDecoder::input)                         */
    std::uint8_t buf[8192]{};
    int n = 0, len = 0;
    int c;
    while ((c = std::fgetc(fp)) != EOF) {
        std::uint8_t b = static_cast<std::uint8_t>(c);
        if (n == 0) {
            if (b != 0xD3) continue;
            buf[n++] = b;
            continue;
        }
        buf[n++] = b;
        if (n == 3) {
            len = rtcm::getbitu(buf, 14, 10) + 3;
            if (len > 8192 - 3) { n = 0; continue; }
        }
        if (n < 3 || n < len + 3) continue;

        std::uint32_t want = rtcm::getbitu(buf, len * 8, 24);
        if (rtcm::RtcmDecoder::crc24q(buf, len) == want) {
            int type = static_cast<int>(rtcm::getbitu(buf, 24, 12));
            count[type]++;
            total++;
            if (type == 4090) {
                int subType = static_cast<int>(rtcm::getbitu(buf, 36, 4));
                int mNo     = static_cast<int>(rtcm::getbitu(buf, 40, 8));
                static std::map<int, long> mNoMap;
                static std::map<int, long> subMap;
                mNoMap[mNo]++;
                subMap[subType]++;
            }
        } else {
            bad_crc++;
        }
        n = 0;
    }
    std::fclose(fp);

    std::printf("total messages (CRC-OK): %ld   bad-CRC: %ld\n", total, bad_crc);
    std::printf("type  count\n----  -----\n");
    for (auto& kv : count) std::printf("%4d  %ld\n", kv.first, kv.second);

    /* re-scan to print 4090 sub-distribution (lazy: just print again) */
    std::printf("\n4090 subType / mNo distribution\n");
    fp = std::fopen(argv[1], "rb");
    std::map<int, long> subMap, mNoMap, lenMap;
    n = 0; len = 0;
    while ((c = std::fgetc(fp)) != EOF) {
        std::uint8_t bb = (std::uint8_t)c;
        if (n == 0) { if (bb != 0xD3) continue; buf[n++] = bb; continue; }
        buf[n++] = bb;
        if (n == 3) { len = rtcm::getbitu(buf, 14, 10) + 3; if (len > 8192 - 3) { n = 0; continue; } }
        if (n < 3 || n < len + 3) continue;
        std::uint32_t want = rtcm::getbitu(buf, len * 8, 24);
        if (rtcm::RtcmDecoder::crc24q(buf, len) == want) {
            int type = (int)rtcm::getbitu(buf, 24, 12);
            if (type == 4090) {
                int subType = (int)rtcm::getbitu(buf, 36, 4);
                int mNo     = (int)rtcm::getbitu(buf, 40, 8);
                subMap[subType]++;
                mNoMap[mNo]++;
                lenMap[len]++;
            }
        }
        n = 0;
    }
    std::fclose(fp);
    std::printf("subType  count\n-------  -----\n");
    for (auto& kv : subMap) std::printf("%4d     %ld\n", kv.first, kv.second);
    std::printf("\nmNo  count\n---  -----\n");
    for (auto& kv : mNoMap) std::printf("%3d  %ld\n", kv.first, kv.second);
    std::printf("\n4090 length distribution (top 10):\n");
    int n_shown = 0;
    for (auto& kv : lenMap) {
        if (n_shown++ >= 10) break;
        std::printf("len=%4d  count=%ld\n", kv.first, kv.second);
    }
    return 0;
}
