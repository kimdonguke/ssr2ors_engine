#!/usr/bin/env python3
"""
SM002 의 c1, c2 비트가 정말로 zero-stream 인지,
아니면 우리 비트 매칭이 어긋났는지 통계로 검증.

방법:
  1) RTCM3 파일을 frame 단위로 읽고 mNo=2 인 SM002 페이로드를 모두 뽑는다.
  2) Java 스펙(record 76 bit, c0@+6/22, c1@+28/21, c2@+49/27, prn@+0/6)으로
     모든 위성 레코드를 추출하고 raw 비트열을 함께 저장한다.
  3) 비트 인덱스별 1-출현 빈도를 계산해 c1/c2 구간이 정말 zero stream인지 본다.
  4) c1/c2 구간이 모두 0이면 → 송신측이 단순히 0 으로 보내고 있다는 결정적 증거.
     일부라도 1이 끼어있으면 → 비트 매칭 또는 스트라이드 오프셋 의심.
"""
import os, sys, struct

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RTCM = os.path.join(ROOT, 'ssr_raw_data_20260510.rtcm3')

CRC24Q_INIT = 0
CRC24Q_POLY = 0x1864CFB

def crc24q(buf):
    crc = 0
    for b in buf:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24Q_POLY
        crc &= 0xFFFFFF
    return crc

def getbitu(buff, pos, ln):
    v = 0
    for i in range(pos, pos + ln):
        v = (v << 1) | ((buff[i >> 3] >> (7 - (i & 7))) & 1)
    return v

def getbits(buff, pos, ln):
    v = getbitu(buff, pos, ln)
    if v & (1 << (ln - 1)):
        v -= (1 << ln)
    return v

def iter_frames(path):
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    n = len(data)
    while i < n:
        if data[i] != 0xD3:
            i += 1
            continue
        if i + 3 > n:
            break
        ln = ((data[i+1] & 0x03) << 8) | data[i+2]
        frame_len = 3 + ln + 3
        if i + frame_len > n:
            break
        payload = data[i:i+3+ln]
        crc_bytes = data[i+3+ln:i+frame_len]
        crc_recv = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]
        crc_calc = crc24q(payload)
        if crc_recv != crc_calc:
            i += 1
            continue
        yield data[i:i+frame_len]
        i += frame_len

# ---------------------------------------------------------------
# 1) SM002 추출
FRAME_HDR = 24   # 0xD3 + length(10) + reserved(6) = 24 bits
sm02_records_raw = []   # 각 위성 레코드 76-bit chunk (bytes)
sm02_records_pos = []   # 시작 비트 위치 (디버깅용)

c0_vals, c1_vals, c2_vals, prns = [], [], [], []

frames = 0
sm02_msgs = 0
for fr in iter_frames(RTCM):
    frames += 1
    # 메시지 타입 = 처음 12 bit @ payload (i.e. bit 24)
    mt = getbitu(fr, FRAME_HDR, 12)
    if mt != 4090:
        continue
    mNo = getbitu(fr, FRAME_HDR + 16, 8)
    if mNo != 2:
        continue
    sm02_msgs += 1

    # SM002 header (Java spec): gs@27..46, gnss@57..60, noSat@61..66
    gnss   = getbitu(fr, FRAME_HDR + 57, 4)
    noSat  = getbitu(fr, FRAME_HDR + 61, 6)
    pos    = 67
    payload_bits = (len(fr) - 3 - 3) * 8  # data section bit count
    for _ in range(noSat):
        if FRAME_HDR + pos + 76 > FRAME_HDR + payload_bits:
            break
        prn_off = getbitu(fr, FRAME_HDR + pos, 6)
        c0 = getbits(fr, FRAME_HDR + pos + 6, 22)
        c1 = getbits(fr, FRAME_HDR + pos + 28, 21)
        c2 = getbits(fr, FRAME_HDR + pos + 49, 27)
        # raw 76 bit chunk → bool list
        chunk = [getbitu(fr, FRAME_HDR + pos + b, 1) for b in range(76)]
        sm02_records_raw.append(chunk)
        sm02_records_pos.append((sm02_msgs, pos))
        c0_vals.append(c0); c1_vals.append(c1); c2_vals.append(c2); prns.append(prn_off)
        pos += 76

print(f"Total frames   : {frames}")
print(f"SM002 messages : {sm02_msgs}")
print(f"Sat records    : {len(sm02_records_raw)}")
print()
print(f"c0 nonzero count: {sum(1 for v in c0_vals if v != 0)} / {len(c0_vals)}")
print(f"c1 nonzero count: {sum(1 for v in c1_vals if v != 0)} / {len(c1_vals)}")
print(f"c2 nonzero count: {sum(1 for v in c2_vals if v != 0)} / {len(c2_vals)}")
print(f"c0 range        : [{min(c0_vals)*1e-4:.4f}, {max(c0_vals)*1e-4:.4f}] m")
print(f"c1 range        : [{min(c1_vals)*1e-6:.6f}, {max(c1_vals)*1e-6:.6f}] m/s")
print(f"c2 range        : [{min(c2_vals)*2e-8:.10f}, {max(c2_vals)*2e-8:.10f}] m/s²")
print()

# ---------------------------------------------------------------
# 2) 비트별 1-출현 빈도
n = len(sm02_records_raw)
ones_per_bit = [0] * 76
for chunk in sm02_records_raw:
    for b, v in enumerate(chunk):
        ones_per_bit[b] += v

print("Bit-by-bit '1' frequency over all 76-bit records:")
print("  pos | bits | ones / total | meaning")
print("  ----+------+--------------+--------")
spans = [(0, 6,  'prn'),
         (6, 22, 'c0 (22b)'),
         (28,21, 'c1 (21b)'),
         (49,27, 'c2 (27b)')]
for start, ln, name in spans:
    print(f"  --- {name} @+{start}..{start+ln-1} ---")
    for b in range(start, start + ln):
        ones = ones_per_bit[b]
        flag = ''
        if ones == 0:
            flag = ' (constant 0)'
        elif ones == n:
            flag = ' (constant 1)'
        elif 0.4 * n < ones < 0.6 * n:
            flag = ' (~random)'
        print(f"  {b:3d} |      | {ones:5d}/{n:<5d}{flag}")

print()
# ---------------------------------------------------------------
# 3) c0 의 부호 비트(MSB)와 LSB 들이 모두 정상 변하는지 확인
print("Sanity: c0 MSB bit-21 (sign) freq =", ones_per_bit[6])
print("Sanity: c0 LSB bit-27        freq =", ones_per_bit[27])
print("If c1/c2 spans are 0 across ALL records, transmitter sends them as zero.")
