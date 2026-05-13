/* extract a few raw mNo=7, mNo=8 payloads for inspection */
#include "rtcm_decode.hpp"
#include <cstdio>
#include <cstdint>
#include <map>

int main(int argc, char* argv[])
{
    if (argc < 2) return 1;
    std::FILE* fp = std::fopen(argv[1], "rb");
    if (!fp) return 1;

    std::uint8_t buf[8192]{};
    int n = 0, len = 0, c;
    std::map<int, int> shown;

    while ((c = std::fgetc(fp)) != EOF) {
        std::uint8_t b = (std::uint8_t)c;
        if (n == 0) { if (b != 0xD3) continue; buf[n++] = b; continue; }
        buf[n++] = b;
        if (n == 3) { len = rtcm::getbitu(buf, 14, 10) + 3; if (len > 8192 - 3) { n = 0; continue; } }
        if (n < 3 || n < len + 3) continue;
        std::uint32_t want = rtcm::getbitu(buf, len * 8, 24);
        if (rtcm::RtcmDecoder::crc24q(buf, len) == want) {
            int type = (int)rtcm::getbitu(buf, 24, 12);
            if (type == 4090) {
                int mNo = (int)rtcm::getbitu(buf, 40, 8);
                if ((mNo == 7 || mNo == 8) && shown[mNo] < 3) {
                    shown[mNo]++;
                    int payload_bytes = len - 3;
                    int payload_bits  = payload_bytes * 8;
                    std::printf("=== mNo=%d  len=%d bytes  payload=%d bits ===\n",
                                mNo, len, payload_bits);
                    /* raw hex of payload (skip 3-byte header) */
                    std::printf("payload hex: ");
                    for (int i = 3; i < len; i++) std::printf("%02X ", buf[i]);
                    std::printf("\n");
                    /* full bit string */
                    std::printf("payload bin: ");
                    for (int i = 24; i < len * 8; i++) {
                        std::printf("%d", (int)rtcm::getbitu(buf, i, 1));
                        if ((i - 23) % 8 == 0) std::printf(" ");
                    }
                    std::printf("\n");
                    /* try to decode possible fields */
                    std::printf("  type    (bit  0..11) = %d\n", (int)rtcm::getbitu(buf, 24, 12));
                    std::printf("  subType (bit 12..15) = %d\n", (int)rtcm::getbitu(buf, 36, 4));
                    std::printf("  mNo     (bit 16..23) = %d\n", (int)rtcm::getbitu(buf, 40, 8));
                    std::printf("  ver?    (bit 24..26) = %d\n", (int)rtcm::getbitu(buf, 48, 3));
                    std::printf("  gs?     (bit 27..46) = %d (TOW sec)\n", (int)rtcm::getbitu(buf, 51, 20));
                    std::printf("  ui?     (bit 47..50) = %d\n", (int)rtcm::getbitu(buf, 71, 4));
                    std::printf("  mmi?    (bit 51)     = %d\n", (int)rtcm::getbitu(buf, 75, 1));
                    std::printf("  bit 52..55           = %d\n", (int)rtcm::getbitu(buf, 76, 4));
                    std::printf("  bit 56..63           = 0x%02X\n", (int)rtcm::getbitu(buf, 80, 8));
                    std::printf("  bit 64..71           = 0x%02X\n", (int)rtcm::getbitu(buf, 88, 8));
                    if (payload_bits >= 88) {
                        std::printf("  bit 72..87 (provID?) = %d\n", (int)rtcm::getbitu(buf, 96, 16));
                    }
                    std::printf("\n");
                }
            }
        }
        n = 0;
        if (shown[7] >= 3 && shown[8] >= 3) break;
    }
    std::fclose(fp);
    return 0;
}
