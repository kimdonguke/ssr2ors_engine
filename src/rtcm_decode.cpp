/*------------------------------------------------------------------------------
* rtcm_decode.cpp : RTCM3 SSR message decoder (standalone, no RTKLIB)
*
*   Port of RTKLIB rtcm.c / rtcm3.c (Copyright 2009-2018 T.Takasu) SSR paths.
*-----------------------------------------------------------------------------*/
#include "rtcm_decode.hpp"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace rtcm {

/* ---- constants ----------------------------------------------------------*/
constexpr std::uint8_t RTCM3_PREAMB = 0xD3;

static const double ssr_udi[16] = {
    1, 2, 5, 10, 15, 30, 60, 120, 240, 300, 600, 900, 1800, 3600, 7200, 10800
};

/* SSR code-bias mode -> ObsCode mapping (rtcm3.c codes_xxx[]) -------------*/
static const int codes_gps[] = {
    CODE_L1C, CODE_L1P, CODE_L1W, CODE_L1Y, CODE_L1M,
    CODE_L2C, CODE_L2D, CODE_L2S, CODE_L2L, CODE_L2X, CODE_L2P, CODE_L2W, CODE_L2Y, CODE_L2M,
    CODE_L5I, CODE_L5Q, CODE_L5X
};
static const int codes_glo[] = {
    CODE_L1C, CODE_L1P, CODE_L2C, CODE_L2P
};
static const int codes_gal[] = {
    CODE_L1A, CODE_L1B, CODE_L1C, CODE_L1X, CODE_L1Z,
    CODE_L5I, CODE_L5Q, CODE_L5X,
    CODE_L7I, CODE_L7Q, CODE_L7X,
    CODE_L8I, CODE_L8Q, CODE_L8X,
    CODE_L6A, CODE_L6B, CODE_L6C, CODE_L6X, CODE_L6Z
};
static const int codes_qzs[] = {
    CODE_L1C, CODE_L1S, CODE_L1L,
    CODE_L2S, CODE_L2L, CODE_L2X,
    CODE_L5I, CODE_L5Q, CODE_L5X,
    CODE_L6S, CODE_L6L, CODE_L6X,
    CODE_L1X
};
static const int codes_bds[] = {
    CODE_L1I, CODE_L1Q, CODE_L1X,
    CODE_L7I, CODE_L7Q, CODE_L7X,
    CODE_L6I, CODE_L6Q, CODE_L6X
};
static const int codes_sbs[] = {
    CODE_L1C, CODE_L5I, CODE_L5Q, CODE_L5X
};

/* ---- bit accessors ------------------------------------------------------*/
std::uint32_t getbitu(const std::uint8_t* buff, int pos, int len)
{
    std::uint32_t bits = 0;
    for (int i = pos; i < pos + len; i++) {
        bits = (bits << 1) + ((buff[i / 8] >> (7 - i % 8)) & 1u);
    }
    return bits;
}

std::int32_t getbits(const std::uint8_t* buff, int pos, int len)
{
    std::uint32_t bits = getbitu(buff, pos, len);
    if (len <= 0 || len >= 32 || !(bits & (1u << (len - 1)))) {
        return static_cast<std::int32_t>(bits);
    }
    return static_cast<std::int32_t>(bits | (~0u << len));   /* sign extend */
}

/* ---- CRC-24Q (Qualcomm) -------------------------------------------------*/
static const std::uint32_t tbl_CRC24Q[256] = {
    0x000000,0x864CFB,0x8AD50D,0x0C99F6,0x93E6E1,0x15AA1A,0x1933EC,0x9F7F17,
    0xA18139,0x27CDC2,0x2B5434,0xAD18CF,0x3267D8,0xB42B23,0xB8B2D5,0x3EFE2E,
    0xC54E89,0x430272,0x4F9B84,0xC9D77F,0x56A868,0xD0E493,0xDC7D65,0x5A319E,
    0x64CFB0,0xE2834B,0xEE1ABD,0x685646,0xF72951,0x7165AA,0x7DFC5C,0xFBB0A7,
    0x0CD1E9,0x8A9D12,0x8604E4,0x00481F,0x9F3708,0x197BF3,0x15E205,0x93AEFE,
    0xAD50D0,0x2B1C2B,0x2785DD,0xA1C926,0x3EB631,0xB8FACA,0xB4633C,0x322FC7,
    0xC99F60,0x4FD39B,0x434A6D,0xC50696,0x5A7981,0xDC357A,0xD0AC8C,0x56E077,
    0x681E59,0xEE52A2,0xE2CB54,0x6487AF,0xFBF8B8,0x7DB443,0x712DB5,0xF7614E,
    0x19A3D2,0x9FEF29,0x9376DF,0x153A24,0x8A4533,0x0C09C8,0x00903E,0x86DCC5,
    0xB822EB,0x3E6E10,0x32F7E6,0xB4BB1D,0x2BC40A,0xAD88F1,0xA11107,0x275DFC,
    0xDCED5B,0x5AA1A0,0x563856,0xD074AD,0x4F0BBA,0xC94741,0xC5DEB7,0x43924C,
    0x7D6C62,0xFB2099,0xF7B96F,0x71F594,0xEE8A83,0x68C678,0x645F8E,0xE21375,
    0x15723B,0x933EC0,0x9FA736,0x19EBCD,0x8694DA,0x00D821,0x0C41D7,0x8A0D2C,
    0xB4F302,0x32BFF9,0x3E260F,0xB86AF4,0x2715E3,0xA15918,0xADC0EE,0x2B8C15,
    0xD03CB2,0x567049,0x5AE9BF,0xDCA544,0x43DA53,0xC596A8,0xC90F5E,0x4F43A5,
    0x71BD8B,0xF7F170,0xFB6886,0x7D247D,0xE25B6A,0x641791,0x688E67,0xEEC29C,
    0x3347A4,0xB50B5F,0xB992A9,0x3FDE52,0xA0A145,0x26EDBE,0x2A7448,0xAC38B3,
    0x92C69D,0x148A66,0x181390,0x9E5F6B,0x01207C,0x876C87,0x8BF571,0x0DB98A,
    0xF6092D,0x7045D6,0x7CDC20,0xFA90DB,0x65EFCC,0xE3A337,0xEF3AC1,0x69763A,
    0x578814,0xD1C4EF,0xDD5D19,0x5B11E2,0xC46EF5,0x42220E,0x4EBBF8,0xC8F703,
    0x3F964D,0xB9DAB6,0xB54340,0x330FBB,0xAC70AC,0x2A3C57,0x26A5A1,0xA0E95A,
    0x9E1774,0x185B8F,0x14C279,0x928E82,0x0DF195,0x8BBD6E,0x872498,0x016863,
    0xFAD8C4,0x7C943F,0x700DC9,0xF64132,0x693E25,0xEF72DE,0xE3EB28,0x65A7D3,
    0x5B59FD,0xDD1506,0xD18CF0,0x57C00B,0xC8BF1C,0x4EF3E7,0x426A11,0xC426EA,
    0x2AE476,0xACA88D,0xA0317B,0x267D80,0xB90297,0x3F4E6C,0x33D79A,0xB59B61,
    0x8B654F,0x0D29B4,0x01B042,0x87FCB9,0x1883AE,0x9ECF55,0x9256A3,0x141A58,
    0xEFAAFF,0x69E604,0x657FF2,0xE33309,0x7C4C1E,0xFA00E5,0xF69913,0x70D5E8,
    0x4E2BC6,0xC8673D,0xC4FECB,0x42B230,0xDDCD27,0x5B81DC,0x57182A,0xD154D1,
    0x26359F,0xA07964,0xACE092,0x2AAC69,0xB5D37E,0x339F85,0x3F0673,0xB94A88,
    0x87B4A6,0x01F85D,0x0D61AB,0x8B2D50,0x145247,0x921EBC,0x9E874A,0x18CBB1,
    0xE37B16,0x6537ED,0x69AE1B,0xEFE2E0,0x709DF7,0xF6D10C,0xFA48FA,0x7C0401,
    0x42FA2F,0xC4B6D4,0xC82F22,0x4E63D9,0xD11CCE,0x575035,0x5BC9C3,0xDD8538
};

std::uint32_t RtcmDecoder::crc24q(const std::uint8_t* buff, int len)
{
    std::uint32_t crc = 0;
    for (int i = 0; i < len; i++) {
        crc = ((crc << 8) & 0xFFFFFFu) ^ tbl_CRC24Q[((crc >> 16) ^ buff[i]) & 0xFFu];
    }
    return crc;
}

/* ---- satellite numbering ------------------------------------------------*/
int RtcmDecoder::satNo(int sys, int prn)
{
    if (prn <= 0) return 0;
    switch (sys) {
    case SYS_GPS:
        if (prn < MINPRNGPS || prn > MAXPRNGPS) return 0;
        return prn - MINPRNGPS + 1;
    case SYS_GLO:
        if (prn < MINPRNGLO || prn > MAXPRNGLO) return 0;
        return NSATGPS + prn - MINPRNGLO + 1;
    case SYS_GAL:
        if (prn < MINPRNGAL || prn > MAXPRNGAL) return 0;
        return NSATGPS + NSATGLO + prn - MINPRNGAL + 1;
    case SYS_QZS:
        if (prn < MINPRNQZS || prn > MAXPRNQZS) return 0;
        return NSATGPS + NSATGLO + NSATGAL + prn - MINPRNQZS + 1;
    case SYS_CMP:
        if (prn < MINPRNCMP || prn > MAXPRNCMP) return 0;
        return NSATGPS + NSATGLO + NSATGAL + NSATQZS + prn - MINPRNCMP + 1;
    case SYS_SBS:
        if (prn < MINPRNSBS || prn > MAXPRNSBS) return 0;
        return NSATGPS + NSATGLO + NSATGAL + NSATQZS + NSATCMP + prn - MINPRNSBS + 1;
    }
    return 0;
}

/* ---- time helpers -------------------------------------------------------*/
/* GPS epoch = 1980-01-06 00:00:00 UTC (= time_t 315964800).
 * UTC->GPS leap-second offset is +18 s since 2017-01-01 (current as of 2026).
 * For SSR week-rollover resolution we only need ±½-week accuracy, so the
 * occasional leap-second drift between updates is harmless.                 */
static constexpr std::time_t GPS_EPOCH_UNIX = 315964800;
static constexpr int         GPS_UTC_LEAPS  = 18;

gtime_t gpst2time(int week, double sec)
{
    gtime_t t{};
    if (sec < -1e9 || sec > 1e9) sec = 0;
    int sec_i = static_cast<int>(std::floor(sec));
    t.time = GPS_EPOCH_UNIX + static_cast<std::time_t>(week) * 604800 + sec_i;
    t.sec  = sec - sec_i;
    return t;
}

double time2gpst(gtime_t t, int* week)
{
    std::time_t sec = t.time - GPS_EPOCH_UNIX;
    int w = static_cast<int>(sec / 604800);
    if (week) *week = w;
    return static_cast<double>(sec - static_cast<std::time_t>(w) * 604800) + t.sec;
}

gtime_t timeadd(gtime_t t, double sec)
{
    t.sec += sec;
    double tt = std::floor(t.sec);
    t.time += static_cast<std::time_t>(tt);
    t.sec  -= tt;
    return t;
}

double timediff(gtime_t a, gtime_t b)
{
    return static_cast<double>(a.time - b.time) + (a.sec - b.sec);
}

gtime_t utc2gpst(gtime_t t)
{
    return timeadd(t, GPS_UTC_LEAPS);
}

gtime_t timeget()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto s   = duration_cast<seconds>(now.time_since_epoch());
    auto us  = duration_cast<microseconds>(now.time_since_epoch() - s);
    gtime_t t;
    t.time = static_cast<std::time_t>(s.count());
    t.sec  = us.count() * 1e-6;
    return utc2gpst(t);
}

/* ---- decoder ------------------------------------------------------------*/
RtcmDecoder::RtcmDecoder() = default;

void RtcmDecoder::setReferenceTime(int gps_week, double tow)
{
    time_     = gpst2time(gps_week, tow);
    time_set_ = true;
}

void RtcmDecoder::clearUpdateFlags()
{
    for (auto& s : ssr_) s.update = 0;
}

void RtcmDecoder::ensureRefTime()
{
    if (time_set_) return;
    if (time_.time == 0) {
        time_ = timeget();
        time_set_ = true;
    }
}

void RtcmDecoder::adjWeek(double tow)
{
    ensureRefTime();
    int week = 0;
    double tow_p = time2gpst(time_, &week);
    if      (tow < tow_p - 302400.0) tow += 604800.0;
    else if (tow > tow_p + 302400.0) tow -= 604800.0;
    time_ = gpst2time(week, tow);
}

void RtcmDecoder::adjDayGlot(double tod)
{
    ensureRefTime();
    /* convert current GPST -> UTC -> Moscow (UTC+3) -> day-of-day */
    gtime_t glo = timeadd(timeadd(time_, -GPS_UTC_LEAPS), 10800.0);
    int week = 0;
    double tow   = time2gpst(glo, &week);
    double tod_p = std::fmod(tow, 86400.0);
    tow -= tod_p;
    if      (tod < tod_p - 43200.0) tod += 86400.0;
    else if (tod > tod_p + 43200.0) tod -= 86400.0;
    gtime_t adj = gpst2time(week, tow + tod);
    time_ = utc2gpst(timeadd(adj, -10800.0));
}

/* ---- frame sync (rtcm.c::input_rtcm3) -----------------------------------*/
int RtcmDecoder::input(std::uint8_t data)
{
    if (nbyte_ == 0) {
        if (data != RTCM3_PREAMB) return INPUT_NONE;
        buff_[nbyte_++] = data;
        return INPUT_NONE;
    }
    if (nbyte_ >= MAXRAWLEN) { nbyte_ = 0; return INPUT_NONE; }
    buff_[nbyte_++] = data;

    if (nbyte_ == 3) {
        len_ = static_cast<int>(getbitu(buff_.data(), 14, 10)) + 3;  /* w/o CRC */
        if (len_ > MAXRAWLEN - 3) { nbyte_ = 0; return INPUT_NONE; }
    }
    if (nbyte_ < 3 || nbyte_ < len_ + 3) return INPUT_NONE;
    nbyte_ = 0;

    /* CRC-24Q check */
    std::uint32_t want = getbitu(buff_.data(), len_ * 8, 24);
    if (crc24q(buff_.data(), len_) != want) return INPUT_NONE;

    return decodeMessage();
}

int RtcmDecoder::input_file(std::FILE* fp)
{
    for (int i = 0; i < 4096; i++) {
        int c = std::fgetc(fp);
        if (c == EOF) return -2;
        int ret = input(static_cast<std::uint8_t>(c));
        if (ret) return ret;
    }
    return INPUT_NONE;
}

/* ---- top-level dispatcher (rtcm3.c::decode_rtcm3) -----------------------*/
int RtcmDecoder::decodeMessage()
{
    int type = static_cast<int>(getbitu(buff_.data(), 24, 12));
    last_           = MsgInfo{};
    last_.type      = type;

    switch (type) {
    /* GPS */
    case 1057: return decodeSSR1(SYS_GPS);
    case 1058: return decodeSSR2(SYS_GPS);
    case 1059: return decodeSSR3(SYS_GPS);
    case 1060: return decodeSSR4(SYS_GPS);
    case 1061: return decodeSSR5(SYS_GPS);
    case 1062: return decodeSSR6(SYS_GPS);
    /* GLONASS */
    case 1063: return decodeSSR1(SYS_GLO);
    case 1064: return decodeSSR2(SYS_GLO);
    case 1065: return decodeSSR3(SYS_GLO);
    case 1066: return decodeSSR4(SYS_GLO);
    case 1067: return decodeSSR5(SYS_GLO);
    case 1068: return decodeSSR6(SYS_GLO);
    /* Galileo (RTCM 3.2 / draft) */
    case 1240: return decodeSSR1(SYS_GAL);
    case 1241: return decodeSSR2(SYS_GAL);
    case 1242: return decodeSSR3(SYS_GAL);
    case 1243: return decodeSSR4(SYS_GAL);
    case 1244: return decodeSSR5(SYS_GAL);
    case 1245: return decodeSSR6(SYS_GAL);
    /* QZSS */
    case 1246: return decodeSSR1(SYS_QZS);
    case 1247: return decodeSSR2(SYS_QZS);
    case 1248: return decodeSSR3(SYS_QZS);
    case 1249: return decodeSSR4(SYS_QZS);
    case 1250: return decodeSSR5(SYS_QZS);
    case 1251: return decodeSSR6(SYS_QZS);
    /* SBAS (draft) */
    case 1252: return decodeSSR1(SYS_SBS);
    case 1253: return decodeSSR2(SYS_SBS);
    case 1254: return decodeSSR3(SYS_SBS);
    case 1255: return decodeSSR4(SYS_SBS);
    case 1256: return decodeSSR5(SYS_SBS);
    case 1257: return decodeSSR6(SYS_SBS);
    /* BeiDou (draft) */
    case 1258: return decodeSSR1(SYS_CMP);
    case 1259: return decodeSSR2(SYS_CMP);
    case 1260: return decodeSSR3(SYS_CMP);
    case 1261: return decodeSSR4(SYS_CMP);
    case 1262: return decodeSSR5(SYS_CMP);
    case 1263: return decodeSSR6(SYS_CMP);
    /* Korean SSR-G proprietary */
    case 4090: return decodeSsrg4090();
    }
    return INPUT_NONE;   /* unknown / unsupported message: ignored */
}

/* ===== SSR-G (RTCM3 MT 4090) ============================================
 *  Java's `buf` is a bit-string of the payload (starts at type field).     *
 *  My `buff_` is the full RTCM3 frame (preamble + length + payload + CRC). *
 *  Therefore every Java bit position needs +24 to address my buffer.       *
 *                                                                          *
 *  Payload-relative layout (per SsrgDecoder.java):                         *
 *    [0..11]   12  msgNo  = 4090                                           *
 *    [12..15]   4  subType (always 2 in observed streams)                  *
 *    [16..23]   8  mNo  (1=SM001..6=SM006; 7/8 observed but undocumented)  *
 *    [24..26]   3  ver                                                     *
 *    [27..46]  20  gs   (GPS seconds-of-week)                              *
 *    [47..50]   4  updateInterval                                          *
 *    [51]       1  multipleMessageIndicator                                *
 *    [52]       1  updateIntervalClass  (mNo != 1)                         *
 *    [53..56]   4  reserved                                                *
 *    [57..60]   4  gnssIndicator   (mNo != 4)                              *
 *    [61]       1  satRefDatum     (mNo == 1)                              *
 *    [62..67]   6  noSat           (mNo == 1)                              *
 *    [61..66]   6  noSat / noGP    (mNo != 1)                              *
 * =========================================================================*/
static constexpr int FRAME_HDR_BITS = 24;   /* preamble + 6+10-bit length  */
int RtcmDecoder::prnPrefix(int g)
{
    switch (g) {
    case 0: return 100;   /* GPS */
    case 1: return 300;   /* GLO */
    case 2: return 400;   /* GAL */
    case 3: return 600;   /* BDS */
    case 4: return 500;   /* QZS */
    case 5: return 200;   /* SBS */
    }
    return 0;
}

/* helper: read unsigned/signed bits at PAYLOAD-relative position (auto +24) */
#define PB(pos, len)  getbitu(buff_.data(), FRAME_HDR_BITS + (pos), (len))
#define PS(pos, len)  getbits(buff_.data(), FRAME_HDR_BITS + (pos), (len))

void RtcmDecoder::decodeSsrgHeader(int /*hasRefd*/)
{
    ssrg_.ver                       = (int)PB(24, 3);
    ssrg_.gs                        = (int)PB(27, 20);
    ssrg_.updateInterval            = (int)PB(47, 4);
    ssrg_.multipleMessageIndicator  = (int)PB(51, 1);
    ssrg_.updateIntervalClass       = (int)PB(52, 1);
}

int RtcmDecoder::decodeSsrg4090()
{
    ssrg_.orbit.clear(); ssrg_.clock.clear(); ssrg_.bias.clear();
    ssrg_.trop .clear(); ssrg_.stec .clear();
    ssrg_.start = SsrgStart{};
    ssrg_.end   = SsrgEnd{};

    int mNo = (int)PB(16, 8);            /* payload bit 16..23 (Java) */
    ssrg_.mNo  = mNo;
    last_.type = 4090;

    /* SM07 / SM08 use a DIFFERENT header layout (no gs at 27..46);          *
     * dispatch them before running the standard SM01-006 header parser.    */
    switch (mNo) {
    case 7: parseSM007(); return INPUT_SSRG;
    case 8: parseSM008(); return INPUT_SSRG;
    }
    decodeSsrgHeader(mNo == 1);
    switch (mNo) {
    case 1: parseSM001(); break;
    case 2: parseSM002(); break;
    case 3: parseSM003(); break;
    case 4: parseSM004(); break;
    case 5: parseSM005(); break;
    case 6: parseSM006(); break;
    default: return INPUT_NONE;          /* mNo 9, 10, 11, ... unknown */
    }
    return INPUT_SSRG;
}

/* available payload bit-length (excluding the 3-byte RTCM3 header)         */
static inline int payloadBits(int len) { return len * 8 - 24; }

/* SM001 — satellite Orbit corrections (Java parseSM001) -------------------*/
void RtcmDecoder::parseSM001()
{
    const int bitLen = payloadBits(len_);

    ssrg_.gnssIndicator = (int)PB(57, 4);
    ssrg_.refd          = (int)PB(61, 1);
    int noSat           = (int)PB(62, 6);
    int pos             = 68;
    int iodBits         = (ssrg_.ver == 0) ? 8 : 11;
    int recBits         = 68 + iodBits;
    int base            = prnPrefix(ssrg_.gnssIndicator);

    for (int i = 0; i < noSat && pos + recBits <= bitLen; i++) {
        SsrgOrbit o;
        o.gs     = ssrg_.gs;
        o.prn    = base + (int)PB(pos, 6);
        o.iod    =        (int)PB(pos + 6, iodBits);
        o.radial = PS(pos +  6 + iodBits, 22) * 1e-4;
        o.along  = PS(pos + 28 + iodBits, 20) * 4e-4;
        o.cross  = PS(pos + 48 + iodBits, 20) * 4e-4;
        ssrg_.orbit.push_back(o);
        pos += recBits;
    }
}

/* SM002 — satellite Clock corrections -------------------------------------*/
void RtcmDecoder::parseSM002()
{
    const int bitLen = payloadBits(len_);

    ssrg_.gnssIndicator = (int)PB(57, 4);
    int noSat           = (int)PB(61, 6);
    int pos             = 67;
    int base            = prnPrefix(ssrg_.gnssIndicator);

    for (int i = 0; i < noSat && pos + 76 <= bitLen; i++) {
        SsrgClock c;
        c.gs  = ssrg_.gs;
        c.prn = base + (int)PB(pos, 6);
        c.c0  = PS(pos +  6, 22) * 1e-4;
        c.c1  = PS(pos + 28, 21) * 1e-6;
        c.c2  = PS(pos + 49, 27) * 2e-8;
        ssrg_.clock.push_back(c);
        pos += 76;
    }
}

/* SM003 — signal (code + phase) Bias --------------------------------------*/
void RtcmDecoder::parseSM003()
{
    const int bitLen = payloadBits(len_);

    ssrg_.gnssIndicator = (int)PB(57, 4);
    int noSat           = (int)PB(61, 6);
    int pos             = 67;
    int base            = prnPrefix(ssrg_.gnssIndicator);

    for (int i = 0; i < noSat; i++) {
        if (pos + 6 > bitLen) break;
        int prn = base + (int)PB(pos, 6);

        if (ssrg_.ver == 0) {
            if (pos + 78 > bitLen) break;
            SsrgBias bA, bB;
            bA.gs = bB.gs = ssrg_.gs;
            bA.prn = bB.prn = prn;
            bA.signalIndex = 0;
            bA.codeBias    = PS(pos +  6, 14) * 0.01;
            bA.phaseBias   = PS(pos + 34, 22) * 1e-4;
            bB.signalIndex = 11;
            bB.codeBias    = PS(pos + 20, 14) * 0.01;
            bB.phaseBias   = PS(pos + 56, 22) * 1e-4;
            ssrg_.bias.push_back(bA);
            ssrg_.bias.push_back(bB);
            pos += 78;
        } else {
            if (pos + 10 > bitLen) break;
            int noSigs = (int)PB(pos + 6, 4);
            int hdr    = (ssrg_.ver == 1) ? 10 : 11;
            int sigSz  = (ssrg_.ver <= 2) ? 45 : 55;
            pos += hdr;
            for (int j = 0; j < noSigs && pos + sigSz <= bitLen; j++) {
                SsrgBias sb;
                sb.gs          = ssrg_.gs;
                sb.prn         = prn;
                sb.signalIndex = (int)PB(pos, 5);
                sb.codeBias    = PS(pos +  5, 14) * 0.01;
                sb.phaseBias   = PS(pos + 19, 22) * 1e-4;
                ssrg_.bias.push_back(sb);
                pos += sigSz;
            }
        }
    }
}

/* SM004 — Tropospheric delay grid -----------------------------------------*/
void RtcmDecoder::parseSM004()
{
    const int bitLen  = payloadBits(len_);
    int       noGP    = (int)PB(57, 6);
    int       pos     = 63;
    int       recBits = (ssrg_.ver <= 1) ? 113 : 115;

    for (int i = 0; i < noGP && pos + recBits <= bitLen; i++) {
        SsrgTrop t;
        t.gs  = ssrg_.gs;
        t.lat = PS(pos +  2, 28) * 1e-6;
        t.lon = PS(pos + 30, 29) * 1e-6;
        t.hgt = PS(pos + 59, 24) * 1e-3;
        if (ssrg_.ver <= 1) {
            t.ztd = PS(pos + 83, 16) * 1e-4;
            t.zwd = PS(pos + 99, 14) * 1e-4;
        } else {
            t.ztd = PS(pos +  83, 18) * 1e-4;
            t.zwd = PS(pos + 101, 14) * 1e-4;
        }
        ssrg_.trop.push_back(t);
        pos += recBits;
    }
}

/* SM005 — Ionospheric STEC grid --------------------------------------------*/
void RtcmDecoder::parseSM005()
{
    const int bitLen = payloadBits(len_);
    ssrg_.gnssIndicator = (int)PB(57, 4);
    int noGP            = (int)PB(61, 6);
    int pos             = 67;
    int base            = prnPrefix(ssrg_.gnssIndicator);

    for (int i = 0; i < noGP && pos + 89 <= bitLen; i++) {
        double lat   = PS(pos +  2, 28) * 1e-6;
        double lon   = PS(pos + 30, 29) * 1e-6;
        double hgt   = PS(pos + 59, 24) * 1e-3;
        int    noSat = (int)PB(pos + 83, 6);
        pos += 89;
        for (int j = 0; j < noSat && pos + 36 <= bitLen; j++) {
            SsrgStec s;
            s.gs   = ssrg_.gs;
            s.lat  = lat; s.lon = lon; s.hgt = hgt;
            s.prn  = base + (int)PB(pos, 6);
            s.stec = PS(pos + 6, 30) * 1e-5;
            ssrg_.stec.push_back(s);
            pos += 36;
        }
    }
}

/* SM006 — Combined Tropo + STEC grid --------------------------------------*/
void RtcmDecoder::parseSM006()
{
    const int bitLen = payloadBits(len_);
    ssrg_.gnssIndicator = (int)PB(57, 4);
    int noGP            = (int)PB(61, 6);
    int pos             = 67;
    int base            = prnPrefix(ssrg_.gnssIndicator);

    for (int i = 0; i < noGP; i++) {
        if (pos + 119 > bitLen) break;
        double lat = PS(pos +  2, 28) * 1e-6;
        double lon = PS(pos + 30, 29) * 1e-6;
        double hgt = PS(pos + 59, 24) * 1e-3;
        double ztd, zwd;
        int    noSat;
        if (ssrg_.ver <= 1) {
            ztd   = PS(pos +  83, 16) * 1e-4;
            zwd   = PS(pos +  99, 14) * 1e-4;
            noSat = (int)PB(pos + 113, 6);
            pos  += 119;
        } else {
            if (pos + 121 > bitLen) break;
            ztd   = PS(pos +  83, 18) * 1e-4;
            zwd   = PS(pos + 101, 14) * 1e-4;
            noSat = (int)PB(pos + 115, 6);
            pos  += 121;
        }
        SsrgTrop t;
        t.gs = ssrg_.gs; t.lat = lat; t.lon = lon; t.hgt = hgt;
        t.ztd = ztd; t.zwd = zwd;
        ssrg_.trop.push_back(t);

        for (int j = 0; j < noSat && pos + 36 <= bitLen; j++) {
            SsrgStec s;
            s.gs   = ssrg_.gs;
            s.lat  = lat; s.lon = lon; s.hgt = hgt;
            s.prn  = base + (int)PB(pos, 6);
            s.stec = PS(pos + 6, 30) * 1e-5;
            ssrg_.stec.push_back(s);
            pos += 36;
        }
    }
}

/* ===== SM07 / SM08 (data block delimiters, reverse-engineered) ==========
 *
 * SM07 (80-bit payload):
 *    bit  0..11  (12)  type      = 4090
 *    bit 12..15  (4)   subType   = 2
 *    bit 16..23  (8)   mNo       = 7
 *    bit 24..26  (3)   version
 *    bit 27..34  (8)   SSR epoch sequence counter (wraps 0..255)
 *    bit 35..37  (3)   reserved (= 0)
 *    bit 38..50  (13)  GPS Week Number
 *    bit 51..70  (20)  GPS Time of Week (s)        — epoch start TOW
 *    bit 71..79  (9)   reserved (= 0)
 *
 * SM08 (88-bit payload):
 *    bit  0..11  (12)  type      = 4090
 *    bit 12..15  (4)   subType   = 2
 *    bit 16..23  (8)   mNo       = 8
 *    bit 24..26  (3)   version
 *    bit 27..34  (8)   epoch sequence counter (= SM07.seq, occasionally +1)
 *    bit 35..54  (20)  GPS Time of Week (s)         — epoch end TOW
 *    bit 55..63  (9)   reserved (= 0)
 *    bit 64..87  (24)  fixed end marker (= 0x102010)
 *
 *  References:
 *    - statistical analysis of 8567 SM07 + 8567 SM08 samples on
 *      ssr_raw_data_20260510.rtcm3 (analyze_sm78_v2.py)
 *    - exact TOW match between SM07/SM08 of same pair (8567/8567)
 *    - GPS Week field equals 2418 (= 2026-05-10) for all samples
 * =========================================================================*/
void RtcmDecoder::parseSM007()
{
    ssrg_.start.ver  = (int)PB(24, 3);
    ssrg_.start.seq  = (int)PB(27, 8);
    /* PB(35,3) reserved */
    ssrg_.start.week = (int)PB(38, 13);
    ssrg_.start.tow  = (int)PB(51, 20);
    /* PB(71,9) reserved */
}

void RtcmDecoder::parseSM008()
{
    ssrg_.end.ver  = (int)PB(24, 3);
    ssrg_.end.seq  = (int)PB(27, 8);
    ssrg_.end.tow  = (int)PB(35, 20);
    /* PB(55,9) reserved */
    ssrg_.end.tail = (int)PB(64, 24);
}

#undef PB
#undef PS

/* ---- SSR 1 / 4 header (rtcm3.c::decode_ssr1_head) -----------------------*/
int RtcmDecoder::decodeSSR1Head(int sys, int& sync, int& iod, double& udint,
                                int& refd, int& hsize)
{
    int i  = 24 + 12;
    int ns = (sys == SYS_QZS) ? 4 : 6;

    if (i + (sys == SYS_GLO ? 53 : 50 + ns) > len_ * 8) return -1;

    if (sys == SYS_GLO) {
        double tod = getbitu(buff_.data(), i, 17); i += 17;
        adjDayGlot(tod);
    } else {
        double tow = getbitu(buff_.data(), i, 20); i += 20;
        adjWeek(tow);
    }
    int udi  = static_cast<int>(getbitu(buff_.data(), i, 4)); i +=  4;
    sync     = static_cast<int>(getbitu(buff_.data(), i, 1)); i +=  1;
    refd     = static_cast<int>(getbitu(buff_.data(), i, 1)); i +=  1;
    iod      = static_cast<int>(getbitu(buff_.data(), i, 4)); i +=  4;
    /* providerId(16) + solutionId(4) skipped */
    i += 16; i += 4;
    int nsat = static_cast<int>(getbitu(buff_.data(), i, ns)); i += ns;
    udint    = ssr_udi[udi & 0xF];
    hsize    = i;

    last_.sys     = sys;
    last_.nsat    = nsat;
    last_.sync    = sync;
    last_.iod_ssr = iod;
    last_.udint   = udint;
    return nsat;
}

/* ---- SSR 2 / 3 / 5 / 6 header (rtcm3.c::decode_ssr2_head) ---------------*/
int RtcmDecoder::decodeSSR2Head(int sys, int& sync, int& iod, double& udint, int& hsize)
{
    int i  = 24 + 12;
    int ns = (sys == SYS_QZS) ? 4 : 6;

    if (i + (sys == SYS_GLO ? 52 : 49 + ns) > len_ * 8) return -1;

    if (sys == SYS_GLO) {
        double tod = getbitu(buff_.data(), i, 17); i += 17;
        adjDayGlot(tod);
    } else {
        double tow = getbitu(buff_.data(), i, 20); i += 20;
        adjWeek(tow);
    }
    int udi  = static_cast<int>(getbitu(buff_.data(), i, 4)); i +=  4;
    sync     = static_cast<int>(getbitu(buff_.data(), i, 1)); i +=  1;
    iod      = static_cast<int>(getbitu(buff_.data(), i, 4)); i +=  4;
    i += 16; i += 4;   /* providerId + solutionId */
    int nsat = static_cast<int>(getbitu(buff_.data(), i, ns)); i += ns;
    udint    = ssr_udi[udi & 0xF];
    hsize    = i;

    last_.sys     = sys;
    last_.nsat    = nsat;
    last_.sync    = sync;
    last_.iod_ssr = iod;
    last_.udint   = udint;
    return nsat;
}

/* per-system PRN field width / offset / iode / iodcrc widths --------------*/
struct SsrSysParam {
    int np;   /* prn bits     */
    int ni;   /* iode bits    */
    int nj;   /* iodcrc bits  */
    int offp; /* prn offset   */
};

static bool ssrSysParam(int sys, SsrSysParam& p)
{
    switch (sys) {
    case SYS_GPS: p = {6,  8,  0,   0}; return true;
    case SYS_GLO: p = {5,  8,  0,   0}; return true;
    case SYS_GAL: p = {6, 10,  0,   0}; return true;
    case SYS_QZS: p = {4,  8,  0, 192}; return true;
    case SYS_CMP: p = {6, 10, 24,   1}; return true;
    case SYS_SBS: p = {6,  9, 24, 120}; return true;
    }
    return false;
}

/* ---- SSR-1: orbit corrections (rtcm3.c::decode_ssr1) --------------------*/
int RtcmDecoder::decodeSSR1(int sys)
{
    int sync = 0, iod = 0, refd = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR1Head(sys, sync, iod, udint, refd, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    for (int j = 0; j < nsat && i + 121 + p.np + p.ni + p.nj <= len_ * 8; j++) {
        int prn    = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        int iode   = static_cast<int>(getbitu(buff_.data(), i, p.ni));          i += p.ni;
        int iodcrc = (p.nj > 0) ? static_cast<int>(getbitu(buff_.data(), i, p.nj)) : 0;
        i += p.nj;
        double deph0  = getbits(buff_.data(), i, 22) * 1e-4; i += 22;
        double deph1  = getbits(buff_.data(), i, 20) * 4e-4; i += 20;
        double deph2  = getbits(buff_.data(), i, 20) * 4e-4; i += 20;
        double ddeph0 = getbits(buff_.data(), i, 21) * 1e-6; i += 21;
        double ddeph1 = getbits(buff_.data(), i, 19) * 4e-6; i += 19;
        double ddeph2 = getbits(buff_.data(), i, 19) * 4e-6; i += 19;

        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[0]  = time_;
        s.udi[0] = udint;
        s.iod[0] = iod;
        s.iode   = iode;
        s.iodcrc = iodcrc;
        s.refd   = refd;
        s.deph [0] = deph0;  s.deph [1] = deph1;  s.deph [2] = deph2;
        s.ddeph[0] = ddeph0; s.ddeph[1] = ddeph1; s.ddeph[2] = ddeph2;
        s.update = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

/* ---- SSR-2: clock corrections (rtcm3.c::decode_ssr2) --------------------*/
int RtcmDecoder::decodeSSR2(int sys)
{
    int sync = 0, iod = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR2Head(sys, sync, iod, udint, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    for (int j = 0; j < nsat && i + 70 + p.np <= len_ * 8; j++) {
        int prn   = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        double c0 = getbits(buff_.data(), i, 22) * 1e-4; i += 22;
        double c1 = getbits(buff_.data(), i, 21) * 1e-6; i += 21;
        double c2 = getbits(buff_.data(), i, 27) * 2e-8; i += 27;

        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[1]   = time_;
        s.udi[1]  = udint;
        s.iod[1]  = iod;
        s.dclk[0] = c0; s.dclk[1] = c1; s.dclk[2] = c2;
        s.update  = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

/* ---- SSR-3: satellite code biases (rtcm3.c::decode_ssr3) ----------------*/
int RtcmDecoder::decodeSSR3(int sys)
{
    int sync = 0, iod = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR2Head(sys, sync, iod, udint, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    const int* codes = nullptr;
    int ncode = 0;
    switch (sys) {
    case SYS_GPS: codes = codes_gps; ncode = 17; break;
    case SYS_GLO: codes = codes_glo; ncode =  4; break;
    case SYS_GAL: codes = codes_gal; ncode = 19; break;
    case SYS_QZS: codes = codes_qzs; ncode = 13; break;
    case SYS_CMP: codes = codes_bds; ncode =  9; break;
    case SYS_SBS: codes = codes_sbs; ncode =  4; break;
    default: return sync ? INPUT_NONE : INPUT_SSR;
    }

    for (int j = 0; j < nsat && i + 5 + p.np <= len_ * 8; j++) {
        int prn   = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        int nbias = static_cast<int>(getbitu(buff_.data(), i, 5));             i +=  5;

        float cbias[MAXCODE]{};
        for (int k = 0; k < nbias && i + 19 <= len_ * 8; k++) {
            int    mode = static_cast<int>(getbitu(buff_.data(), i, 5));    i +=  5;
            double bias = getbits(buff_.data(), i, 14) * 0.01;              i += 14;
            if (mode < ncode) cbias[codes[mode] - 1] = static_cast<float>(bias);
        }
        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[4]  = time_;
        s.udi[4] = udint;
        s.iod[4] = iod;
        std::memcpy(s.cbias, cbias, sizeof(s.cbias));
        s.update = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

/* ---- SSR-4: combined orbit + clock (rtcm3.c::decode_ssr4) ---------------*/
int RtcmDecoder::decodeSSR4(int sys)
{
    int sync = 0, iod = 0, refd = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR1Head(sys, sync, iod, udint, refd, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    for (int j = 0; j < nsat && i + 191 + p.np + p.ni + p.nj <= len_ * 8; j++) {
        int prn    = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        int iode   = static_cast<int>(getbitu(buff_.data(), i, p.ni));          i += p.ni;
        int iodcrc = (p.nj > 0) ? static_cast<int>(getbitu(buff_.data(), i, p.nj)) : 0;
        i += p.nj;
        double deph0  = getbits(buff_.data(), i, 22) * 1e-4; i += 22;
        double deph1  = getbits(buff_.data(), i, 20) * 4e-4; i += 20;
        double deph2  = getbits(buff_.data(), i, 20) * 4e-4; i += 20;
        double ddeph0 = getbits(buff_.data(), i, 21) * 1e-6; i += 21;
        double ddeph1 = getbits(buff_.data(), i, 19) * 4e-6; i += 19;
        double ddeph2 = getbits(buff_.data(), i, 19) * 4e-6; i += 19;
        double dclk0  = getbits(buff_.data(), i, 22) * 1e-4; i += 22;
        double dclk1  = getbits(buff_.data(), i, 21) * 1e-6; i += 21;
        double dclk2  = getbits(buff_.data(), i, 27) * 2e-8; i += 27;

        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[0]  = s.t0[1]  = time_;
        s.udi[0] = s.udi[1] = udint;
        s.iod[0] = s.iod[1] = iod;
        s.iode   = iode;
        s.iodcrc = iodcrc;
        s.refd   = refd;
        s.deph [0] = deph0;  s.deph [1] = deph1;  s.deph [2] = deph2;
        s.ddeph[0] = ddeph0; s.ddeph[1] = ddeph1; s.ddeph[2] = ddeph2;
        s.dclk [0] = dclk0;  s.dclk [1] = dclk1;  s.dclk [2] = dclk2;
        s.update = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

/* ---- SSR-5: URA (rtcm3.c::decode_ssr5) ----------------------------------*/
int RtcmDecoder::decodeSSR5(int sys)
{
    int sync = 0, iod = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR2Head(sys, sync, iod, udint, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    for (int j = 0; j < nsat && i + 6 + p.np <= len_ * 8; j++) {
        int prn = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        int ura = static_cast<int>(getbitu(buff_.data(), i, 6));             i +=  6;

        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[3]  = time_;
        s.udi[3] = udint;
        s.iod[3] = iod;
        s.ura    = ura;
        s.update = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

/* ---- SSR-6: high-rate clock (rtcm3.c::decode_ssr6) ----------------------*/
int RtcmDecoder::decodeSSR6(int sys)
{
    int sync = 0, iod = 0, i = 0;
    double udint = 0;
    int nsat = decodeSSR2Head(sys, sync, iod, udint, i);
    if (nsat < 0) return INPUT_ERROR;

    SsrSysParam p{};
    if (!ssrSysParam(sys, p)) return sync ? INPUT_NONE : INPUT_SSR;

    for (int j = 0; j < nsat && i + 22 + p.np <= len_ * 8; j++) {
        int    prn   = static_cast<int>(getbitu(buff_.data(), i, p.np)) + p.offp; i += p.np;
        double hrclk = getbits(buff_.data(), i, 22) * 1e-4;                       i += 22;

        int sat = satNo(sys, prn);
        if (!sat) continue;
        ssr_t& s = ssr_[sat - 1];
        s.t0[2]  = time_;
        s.udi[2] = udint;
        s.iod[2] = iod;
        s.hrclk  = hrclk;
        s.update = 1;
    }
    return sync ? INPUT_NONE : INPUT_SSR;
}

} /* namespace rtcm */
