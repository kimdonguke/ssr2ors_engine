/*------------------------------------------------------------------------------
* main.cpp : SSR2OSR_engine decoder driver
*
*   usage: SSR2OSR <rtcm3.bin> [dump.txt]
*       reads an RTCM3 byte stream, decodes both
*         (a) standard RTCM3 SSR (MT 1057-1068, 1240-1263), and
*         (b) Korean SSR-G proprietary (MT 4090, SM001-SM006),
*       and writes a deterministic per-message text dump.
*-----------------------------------------------------------------------------*/
#include "rtcm_decode.hpp"

#include <cstdio>
#include <cstdint>
#include <map>

static void dumpSsrSat(std::FILE* out, int sat, const rtcm::ssr_t& s)
{
    std::fprintf(out,
        "  sat=%3d iode=%3d iodcrc=%5d ura=%2d refd=%d"
        " iod=[%2d %2d %2d %2d %2d]"
        " udi=[%6.1f %6.1f %6.1f %6.1f %6.1f]"
        " t0=[%ld.%06d %ld.%06d %ld.%06d %ld.%06d %ld.%06d]"
        " deph=[%+.6f %+.6f %+.6f]"
        " ddeph=[%+.9f %+.9f %+.9f]"
        " dclk=[%+.6f %+.9f %+.11f]"
        " hrclk=%+.6f",
        sat, s.iode, s.iodcrc, s.ura, s.refd,
        s.iod[0], s.iod[1], s.iod[2], s.iod[3], s.iod[4],
        s.udi[0], s.udi[1], s.udi[2], s.udi[3], s.udi[4],
        (long)s.t0[0].time, (int)(s.t0[0].sec*1e6+0.5),
        (long)s.t0[1].time, (int)(s.t0[1].sec*1e6+0.5),
        (long)s.t0[2].time, (int)(s.t0[2].sec*1e6+0.5),
        (long)s.t0[3].time, (int)(s.t0[3].sec*1e6+0.5),
        (long)s.t0[4].time, (int)(s.t0[4].sec*1e6+0.5),
        s.deph [0], s.deph [1], s.deph [2],
        s.ddeph[0], s.ddeph[1], s.ddeph[2],
        s.dclk [0], s.dclk [1], s.dclk [2],
        s.hrclk);
    for (int k = 0; k < rtcm::MAXCODE; k++) {
        if (s.cbias[k] != 0.0f) std::fprintf(out, " cb[%d]=%+.4f", k + 1, s.cbias[k]);
    }
    std::fputc('\n', out);
}

static void dumpSsrg(std::FILE* out, const rtcm::SsrgMessage& m)
{
    std::fprintf(out,
        "MT4090 mNo=%d ver=%d gs=%d gnss=%d refd=%d mmi=%d uic=%d ui=%d "
        "noOrb=%d noClk=%d noBias=%d noTrop=%d noStec=%d\n",
        m.mNo, m.ver, m.gs, m.gnssIndicator, m.refd,
        m.multipleMessageIndicator, m.updateIntervalClass, m.updateInterval,
        (int)m.orbit.size(), (int)m.clock.size(), (int)m.bias.size(),
        (int)m.trop.size(), (int)m.stec.size());

    for (const auto& o : m.orbit)
        std::fprintf(out, "  ORB gs=%d prn=%3d iod=%4d rad=%+.4f alt=%+.4f crt=%+.4f\n",
                     o.gs, o.prn, o.iod, o.radial, o.along, o.cross);
    for (const auto& c : m.clock)
        std::fprintf(out, "  CLK gs=%d prn=%3d c0=%+.4f c1=%+.6f c2=%+.10f\n",
                     c.gs, c.prn, c.c0, c.c1, c.c2);
    for (const auto& b : m.bias)
        std::fprintf(out, "  BIAS gs=%d prn=%3d sig=%2d code=%+.4f phase=%+.4f\n",
                     b.gs, b.prn, b.signalIndex, b.codeBias, b.phaseBias);
    for (const auto& t : m.trop)
        std::fprintf(out, "  TROP gs=%d lat=%+10.6f lon=%+11.6f hgt=%+9.3f ztd=%+.4f zwd=%+.4f\n",
                     t.gs, t.lat, t.lon, t.hgt, t.ztd, t.zwd);
    for (const auto& s : m.stec)
        std::fprintf(out, "  STEC gs=%d lat=%+10.6f lon=%+11.6f hgt=%+9.3f prn=%3d stec=%+.5f\n",
                     s.gs, s.lat, s.lon, s.hgt, s.prn, s.stec);
}

int main(int argc, char* argv[])
{
    if (argc < 2) { std::fprintf(stderr, "usage: %s <rtcm3-stream> [dump.txt]\n", argv[0]); return 1; }
    std::FILE* fp = std::fopen(argv[1], "rb");
    if (!fp) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    std::FILE* out = (argc >= 3) ? std::fopen(argv[2], "w") : stdout;
    if (!out) { std::fprintf(stderr, "cannot write %s\n", argv[2]); return 1; }

    rtcm::RtcmDecoder dec;

    int  byte;
    long n_ssr = 0, n_ssrg = 0;
    std::map<int, long> mNo_counts;

    while ((byte = std::fgetc(fp)) != EOF) {
        int ret = dec.input(static_cast<std::uint8_t>(byte));
        if (ret == rtcm::INPUT_SSR) {
            const auto& m = dec.lastMsg();
            std::fprintf(out, "MT%-4d sys=%d nsat=%2d sync=%d iod=%2d udi=%6.1f\n",
                         m.type, m.sys, m.nsat, m.sync, m.iod_ssr, m.udint);
            for (int sat = 1; sat <= rtcm::MAXSAT; sat++) {
                const auto& s = dec.ssr(sat);
                if (s.update) dumpSsrSat(out, sat, s);
            }
            dec.clearUpdateFlags();
            n_ssr++;
        } else if (ret == rtcm::INPUT_SSRG) {
            const auto& m = dec.lastSsrg();
            dumpSsrg(out, m);
            mNo_counts[m.mNo]++;
            n_ssrg++;
        }
    }
    std::fclose(fp);
    if (out != stdout) std::fclose(out);

    std::fprintf(stderr, "standard SSR: %ld   SSR-G (4090): %ld\n", n_ssr, n_ssrg);
    for (auto& kv : mNo_counts)
        std::fprintf(stderr, "  SM%03d : %ld\n", kv.first, kv.second);
    return 0;
}
