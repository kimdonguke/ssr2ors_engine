/*------------------------------------------------------------------------------
* rtcm_decode.hpp : RTCM3 SSR message decoder (standalone, no RTKLIB)
*
*   Supported messages
*     1057-1062 : SSR GPS    (orbit / clock / code-bias / orb+clk / URA / hrclk)
*     1063-1068 : SSR GLONASS
*     1240-1245 : SSR Galileo
*     1246-1251 : SSR QZSS
*     1252-1257 : SSR SBAS   (draft)
*     1258-1263 : SSR BeiDou (draft)
*
*   Reference: RTKLIB-master/src/rtcm.c, rtcm3.c (T.Takasu)
*-----------------------------------------------------------------------------*/
#pragma once

#include <cstdint>
#include <ctime>
#include <array>
#include <vector>
#include <string>

namespace rtcm {

/* ---- system / size constants ---------------------------------------------*/
constexpr int SYS_NONE = 0x00;
constexpr int SYS_GPS  = 0x01;
constexpr int SYS_SBS  = 0x02;
constexpr int SYS_GLO  = 0x04;
constexpr int SYS_GAL  = 0x08;
constexpr int SYS_QZS  = 0x10;
constexpr int SYS_CMP  = 0x20;

constexpr int MINPRNGPS = 1,   MAXPRNGPS = 32;  constexpr int NSATGPS = 32;
constexpr int MINPRNGLO = 1,   MAXPRNGLO = 24;  constexpr int NSATGLO = 24;
constexpr int MINPRNGAL = 1,   MAXPRNGAL = 30;  constexpr int NSATGAL = 30;
constexpr int MINPRNQZS = 193, MAXPRNQZS = 199; constexpr int NSATQZS = 7;
constexpr int MINPRNCMP = 1,   MAXPRNCMP = 35;  constexpr int NSATCMP = 35;
constexpr int MINPRNSBS = 120, MAXPRNSBS = 142; constexpr int NSATSBS = 23;
constexpr int MAXSAT    = NSATGPS + NSATGLO + NSATGAL + NSATQZS + NSATCMP + NSATSBS;

constexpr int MAXCODE   = 48;     /* max obs code id (1..48) */
constexpr int MAXRAWLEN = 8192;   /* receive buffer length */

/* obs code ids (subset, needed for SSR code-bias mode mapping) -------------*/
enum ObsCode : int {
    CODE_NONE = 0,
    CODE_L1C  = 1,  CODE_L1P = 2,  CODE_L1W = 3,  CODE_L1Y = 4,  CODE_L1M = 5,
    CODE_L1N  = 6,  CODE_L1S = 7,  CODE_L1L = 8,  CODE_L1E = 9,  CODE_L1A = 10,
    CODE_L1B  = 11, CODE_L1X = 12, CODE_L1Z = 13,
    CODE_L2C  = 14, CODE_L2D = 15, CODE_L2S = 16, CODE_L2L = 17, CODE_L2X = 18,
    CODE_L2P  = 19, CODE_L2W = 20, CODE_L2Y = 21, CODE_L2M = 22, CODE_L2N = 23,
    CODE_L5I  = 24, CODE_L5Q = 25, CODE_L5X = 26,
    CODE_L7I  = 27, CODE_L7Q = 28, CODE_L7X = 29,
    CODE_L6A  = 30, CODE_L6B = 31, CODE_L6C = 32, CODE_L6X = 33, CODE_L6Z = 34,
    CODE_L6S  = 35, CODE_L6L = 36,
    CODE_L8I  = 37, CODE_L8Q = 38, CODE_L8X = 39,
    CODE_L2I  = 40, CODE_L2Q = 41,
    CODE_L6I  = 42, CODE_L6Q = 43,
    CODE_L3I  = 44, CODE_L3Q = 45, CODE_L3X = 46,
    CODE_L1I  = 47, CODE_L1Q = 48
};

/* return codes from input_data() -------------------------------------------*/
enum InputStatus : int {
    INPUT_ERROR   = -1,
    INPUT_NONE    =  0,
    INPUT_OBS     =  1,
    INPUT_EPH     =  2,
    INPUT_STATION =  5,
    INPUT_SSR     = 10,   /* standard RTCM3 SSR (MT 1057-1068, 1240-1263) */
    INPUT_SSRG    = 11    /* Korean SSR-G proprietary (MT 4090, SM001-006) */
};

/* ---- SSR-G (RTCM3 MT 4090) types -----------------------------------------*
 *  Reference: SsrgDecoder.java (PpSoln Inc.) — Korean NGII SSR service.    *
 *  GNSS indicator -> PRN-prefix mapping (Java _prnHeader):                  *
 *      0 -> 100 (GPS, e.g. G01 = 101)  1 -> 300 (GLO)                       *
 *      2 -> 400 (GAL)                  3 -> 600 (BDS)                       *
 *      4 -> 500 (QZS)                  5 -> 200 (SBS)                       *
 *  NB: this is NOT RTKLIB's satno() ordering.                               *
 *--------------------------------------------------------------------------*/
struct SsrgOrbit {
    int    gs   = 0;     /* GPS seconds-of-week of the message epoch         */
    int    prn  = 0;     /* PRN with prefix (101..2xx, 301.., 401.., 501..)  */
    int    iod  = 0;     /* IODE (8 or 11 bits depending on ver)             */
    double radial = 0;   /* m */
    double along  = 0;   /* m */
    double cross  = 0;   /* m */
};

struct SsrgClock {
    int    gs  = 0;
    int    prn = 0;
    double c0  = 0;      /* m       */
    double c1  = 0;      /* m/s     */
    double c2  = 0;      /* m/s^2   */
};

struct SsrgBias {
    int    gs          = 0;
    int    prn         = 0;
    int    signalIndex = 0;   /* ver=0: 0 = L1C/A, 11 = L2P (Java legacy);   *
                               * ver>=1: 5-bit signal id from stream         */
    double codeBias    = 0;   /* m  */
    double phaseBias   = 0;   /* m  */
};

struct SsrgTrop {
    int    gs  = 0;
    double lat = 0;       /* deg */
    double lon = 0;       /* deg */
    double hgt = 0;       /* m   */
    double ztd = 0;       /* zenith dry (Tr)  -- m */
    double zwd = 0;       /* zenith wet (Tw)  -- m */
};

struct SsrgStec {
    int    gs   = 0;
    double lat  = 0;     /* deg */
    double lon  = 0;     /* deg */
    double hgt  = 0;     /* m   */
    int    prn  = 0;     /* same prefix scheme as SsrgOrbit */
    double stec = 0;     /* TECu */
};

/* SM07 — data block START marker (reverse-engineered).                     *
 * Carries the GPS week, the TOW of the upcoming epoch, and an 8-bit        *
 * sequence counter that increments once per SSR epoch (wraps at 256).      */
struct SsrgStart {
    int  ver     = 0;     /* always 1 in observed streams           */
    int  seq     = 0;     /* 8-bit epoch sequence counter            */
    int  week    = 0;     /* GPS Week Number                         */
    int  tow     = 0;     /* GPS Time of Week (s)                    */
};

/* SM08 — data block END marker (reverse-engineered).                       *
 * Mirrors SM07 (same TOW, same/+1 sequence counter) plus a fixed           *
 * 24-bit magic tail (0x102010) — likely an end-of-block delimiter.         *
 * The "SM count" the spec mentions has not been located in this stream;    *
 * the 24-bit tail is constant regardless of how many SMs precede SM08.     */
struct SsrgEnd {
    int  ver     = 0;
    int  seq     = 0;
    int  tow     = 0;
    int  tail    = 0;    /* 24-bit fixed marker (= 0x102010) */
};

/* container produced by one 4090 message decode ----------------------------*/
struct SsrgMessage {
    int  mNo  = 0;       /* 1..6 (SM001..SM006)        */
    int  ver  = 0;
    int  gs   = 0;
    int  updateInterval = 0;
    int  multipleMessageIndicator = 0;
    int  updateIntervalClass      = 0;
    int  gnssIndicator            = 0;   /* SM001/2/3/5/6                 */
    int  refd                     = 0;   /* SM001 only                    */

    std::vector<SsrgOrbit> orbit;
    std::vector<SsrgClock> clock;
    std::vector<SsrgBias>  bias;
    std::vector<SsrgTrop>  trop;
    std::vector<SsrgStec>  stec;

    /* SM07 / SM08 (mutually exclusive with the above vectors) */
    SsrgStart start{};   /* valid when mNo == 7 */
    SsrgEnd   end{};     /* valid when mNo == 8 */
};

/* ---- GPS time -------------------------------------------------------------*/
struct gtime_t {
    std::time_t time = 0;  /* integer seconds (POSIX time_t scale) */
    double      sec  = 0;  /* fraction (0..1) */
};

/* ---- SSR correction record (per satellite) -------------------------------*/
/* index of t0[]/udi[]/iod[]: 0=eph, 1=clk, 2=hrclk, 3=ura, 4=bias            */
struct ssr_t {
    gtime_t t0[5]{};
    double  udi[5]{};
    int     iod[5]{};
    int     iode   = 0;
    int     iodcrc = 0;
    int     ura    = 0;
    int     refd   = 0;          /* 0:ITRF, 1:regional */
    double  deph [3]{};          /* orbit  (radial, along, cross) [m]    */
    double  ddeph[3]{};          /* orbit dot                    [m/s]  */
    double  dclk [3]{};          /* clock (c0, c1, c2)           [m, m/s, m/s^2] */
    double  hrclk  = 0;          /* high-rate clock              [m]    */
    float   cbias[MAXCODE]{};    /* code biases                  [m]    */
    std::uint8_t update = 0;     /* set to 1 when any field updated     */
};

/* ---- decoded message metadata -------------------------------------------*/
struct MsgInfo {
    int    type    = 0;   /* RTCM3 message type number (e.g. 1060) */
    int    sys     = 0;   /* SYS_* */
    int    nsat    = 0;
    int    sync    = 0;
    int    iod_ssr = 0;
    double udint   = 0;   /* update interval (s) */
};

/* ---- decoder --------------------------------------------------------------*/
class RtcmDecoder {
public:
    RtcmDecoder();

    /* feed one byte from the stream.                                       *
     * returns one of InputStatus.  on INPUT_SSR / INPUT_OBS the buffered   *
     * message has been fully decoded; metadata can be read from lastMsg(). */
    int input(std::uint8_t data);

    /* feed bytes from a file (returns -2 on EOF, else last InputStatus).   */
    int input_file(std::FILE* fp);

    /* fixed reference time for week-rollover resolution.  if not set, the  *
     * current system clock is used (within ~½ week is enough).             */
    void setReferenceTime(int gps_week, double tow);

    /* accessors */
    const ssr_t&   ssr (int sat) const { return ssr_[sat - 1]; }   /* sat: 1..MAXSAT */
    ssr_t&         ssr (int sat)       { return ssr_[sat - 1]; }
    const MsgInfo& lastMsg() const     { return last_; }
    gtime_t        time() const        { return time_; }
    int            stationId() const   { return staid_; }

    /* SSR-G (MT 4090) decoded message — valid right after input() returns  *
     * INPUT_SSRG; mutated on each subsequent SSR-G frame.                  */
    const SsrgMessage& lastSsrg() const { return ssrg_; }

    /* clear "update" flags after the user has consumed them */
    void clearUpdateFlags();

    /* helpers exposed for testing */
    static int  satNo(int sys, int prn);
    static std::uint32_t crc24q(const std::uint8_t* buff, int len);

private:
    /* frame */
    std::array<std::uint8_t, MAXRAWLEN> buff_{};
    int  nbyte_ = 0;
    int  len_   = 0;
    int  staid_ = 0;
    gtime_t time_{};
    bool time_set_ = false;

    /* state */
    std::array<ssr_t, MAXSAT> ssr_{};
    MsgInfo last_{};
    SsrgMessage ssrg_{};

    /* internals */
    int  decodeMessage();
    int  decodeSSR1(int sys);
    int  decodeSSR2(int sys);
    int  decodeSSR3(int sys);
    int  decodeSSR4(int sys);
    int  decodeSSR5(int sys);
    int  decodeSSR6(int sys);
    int  decodeSSR1Head(int sys, int& sync, int& iod, double& udint, int& refd, int& hsize);
    int  decodeSSR2Head(int sys, int& sync, int& iod, double& udint, int& hsize);

    /* SSR-G (MT 4090) */
    int  decodeSsrg4090();
    void decodeSsrgHeader(int hasRefd);     /* fills ssrg_ common header */
    void parseSM001();
    void parseSM002();
    void parseSM003();
    void parseSM004();
    void parseSM005();
    void parseSM006();
    void parseSM007();   /* data block START marker */
    void parseSM008();   /* data block END marker   */

    static int prnPrefix(int gnssIndicator);

    void adjWeek(double tow);     /* resolve GPS week ambiguity from tow  */
    void adjDayGlot(double tod);  /* resolve GLO day from tod             */
    void ensureRefTime();
};

/* ---- bit accessors (free functions, used by decoder & client) -----------*/
std::uint32_t getbitu(const std::uint8_t* buff, int pos, int len);
std::int32_t  getbits(const std::uint8_t* buff, int pos, int len);

/* ---- time helpers --------------------------------------------------------*/
gtime_t gpst2time(int week, double sec);
double  time2gpst(gtime_t t, int* week);
gtime_t timeadd(gtime_t t, double sec);
double  timediff(gtime_t a, gtime_t b);
gtime_t utc2gpst(gtime_t t);    /* applies GPS-UTC leap-second offset */
gtime_t timeget();              /* current GPS time (from system clock) */

} /* namespace rtcm */
