/*------------------------------------------------------------------------------
* rtklib_ref_decode.c : reference SSR dumper using RTKLIB rtcm.c / rtcm3.c
*
*   produces the same per-message / per-satellite text dump as our C++
*   decoder (main.cpp), allowing byte-for-byte comparison via `diff`.
*
*   link with: rtkcmn.c rtcm.c rtcm2.c rtcm3.c rtcm3e.c
*   build flags: -DENAGLO -DENAQZS -DENAGAL -DENACMP -DTRACE -DWIN32
*-----------------------------------------------------------------------------*/
#include "rtklib.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* derive system code from RTCM3 message type (SSR cases mirror rtcm3.c) ---*/
static int sys_of_type(int type)
{
    if (type >= 1057 && type <= 1062) return SYS_GPS;
    if (type >= 1063 && type <= 1068) return SYS_GLO;
    if (type >= 1240 && type <= 1245) return SYS_GAL;
    if (type >= 1246 && type <= 1251) return SYS_QZS;
    if (type >= 1252 && type <= 1257) return SYS_SBS;
    if (type >= 1258 && type <= 1263) return SYS_CMP;
    return 0;
}

/* per-system header field widths (matches rtcm3.c decode_ssrN_head) -------*/
static int ns_of_sys(int sys) { return sys == SYS_QZS ? 4 : 6; }

/* parse SSR header fields out of the freshly received buffer.              *
 * sub == 1 -> ssr-1/4 header (50+ns / 53 bits) with extra refd bit         *
 * sub == 0 -> ssr-2/3/5/6 header (49+ns / 52 bits)                         */
static void parse_header(const rtcm_t *rtcm, int type, int sub,
                         int *sync, int *iod, double *udint, int *nsat)
{
    static const double udi[16] = {
        1,2,5,10,15,30,60,120,240,300,600,900,1800,3600,7200,10800
    };
    int sys = sys_of_type(type);
    int ns  = ns_of_sys(sys);
    int i   = 24 + 12;
    int v;

    /* skip epoch (TOW 20 bits or TOD 17 bits) */
    i += (sys == SYS_GLO) ? 17 : 20;

    v       = (int)getbitu(rtcm->buff, i, 4); i += 4;        /* udi */
    *udint  = udi[v & 0xF];
    *sync   = (int)getbitu(rtcm->buff, i, 1); i += 1;
    if (sub == 1) { i += 1; }                                /* refd */
    *iod    = (int)getbitu(rtcm->buff, i, 4); i += 4;
    i += 16; i += 4;                                          /* provid+solid */
    *nsat   = (int)getbitu(rtcm->buff, i, ns);
}

static int sub_of_type(int type)
{
    /* SSR-1 (orbit) and SSR-4 (orbit+clock) carry the refd bit             */
    if (type == 1057 || type == 1060) return 1;
    if (type == 1063 || type == 1066) return 1;
    if (type == 1240 || type == 1243) return 1;
    if (type == 1246 || type == 1249) return 1;
    if (type == 1252 || type == 1255) return 1;
    if (type == 1258 || type == 1261) return 1;
    return 0;
}

static void dumpSsrSat(FILE *out, int sat, const ssr_t *s)
{
    int k;
    fprintf(out,
        "  sat=%3d iode=%3d iodcrc=%5d ura=%2d refd=%d"
        " iod=[%2d %2d %2d %2d %2d]"
        " udi=[%6.1f %6.1f %6.1f %6.1f %6.1f]"
        " t0=[%ld.%06d %ld.%06d %ld.%06d %ld.%06d %ld.%06d]"
        " deph=[%+.6f %+.6f %+.6f]"
        " ddeph=[%+.9f %+.9f %+.9f]"
        " dclk=[%+.6f %+.9f %+.11f]"
        " hrclk=%+.6f",
        sat, s->iode, s->iodcrc, s->ura, s->refd,
        s->iod[0], s->iod[1], s->iod[2], s->iod[3], s->iod[4],
        s->udi[0], s->udi[1], s->udi[2], s->udi[3], s->udi[4],
        (long)s->t0[0].time, (int)(s->t0[0].sec*1e6+0.5),
        (long)s->t0[1].time, (int)(s->t0[1].sec*1e6+0.5),
        (long)s->t0[2].time, (int)(s->t0[2].sec*1e6+0.5),
        (long)s->t0[3].time, (int)(s->t0[3].sec*1e6+0.5),
        (long)s->t0[4].time, (int)(s->t0[4].sec*1e6+0.5),
        s->deph [0], s->deph [1], s->deph [2],
        s->ddeph[0], s->ddeph[1], s->ddeph[2],
        s->dclk [0], s->dclk [1], s->dclk [2],
        s->hrclk);

    for (k = 0; k < MAXCODE; k++) {
        if (s->cbias[k] != 0.0f) {
            fprintf(out, " cb[%d]=%+.4f", k + 1, s->cbias[k]);
        }
    }
    fputc('\n', out);
}

int main(int argc, char *argv[])
{
    rtcm_t rtcm;
    FILE *fp, *out = stdout;
    int c, ret, type, sys, sub, sync, iod, nsat, sat;
    long n_msg = 0;
    double udint;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <rtcm3-stream> [dump.txt]\n", argv[0]);
        return 1;
    }
    if (!(fp = fopen(argv[1], "rb"))) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    if (argc >= 3 && !(out = fopen(argv[2], "w"))) {
        fprintf(stderr, "cannot write %s\n", argv[2]);
        return 1;
    }

    if (!init_rtcm(&rtcm)) { fprintf(stderr, "init_rtcm failed\n"); return 1; }

    while ((c = fgetc(fp)) != EOF) {
        ret = input_rtcm3(&rtcm, (unsigned char)c);
        if (ret != 10) continue;             /* 10 == SSR (rtcm.c)         */

        type = (int)getbitu(rtcm.buff, 24, 12);
        sys  = sys_of_type(type);
        sub  = sub_of_type(type);
        parse_header(&rtcm, type, sub, &sync, &iod, &udint, &nsat);

        fprintf(out, "MT%-4d sys=%d nsat=%2d sync=%d iod=%2d udi=%6.1f\n",
                type, sys, nsat, sync, iod, udint);

        for (sat = 1; sat <= MAXSAT; sat++) {
            if (!rtcm.ssr[sat - 1].update) continue;
            dumpSsrSat(out, sat, &rtcm.ssr[sat - 1]);
            rtcm.ssr[sat - 1].update = 0;
        }
        n_msg++;
    }
    fclose(fp);
    if (out != stdout) fclose(out);
    free_rtcm(&rtcm);
    fprintf(stderr, "rtklib: %ld SSR messages decoded.\n", n_msg);
    return 0;
}
