#!/usr/bin/env python3
"""
v3: Sequential analysis - epoch chain inspection.

Confirmed (v1+v2):
  - SM07.bits[27..34] = epoch seq counter, monotonic +1 mod 256
  - SM08.bits[27..34] = SM07.seq         (in 4 SMs epochs: 7139)
  - SM08.bits[27..34] = SM07.seq + 1     (in 16~19 SMs epochs: all 1428)
  - SM06 count varies 4~7, explaining 16/17/18/19 total

NEW hypotheses to test:
  H10: SM08[27..34] is "expected next SM07.seq" (lookahead field)
       -> in 4 SMs epoch (5s clock-only), next SM07.seq = current + 1 (+1 step)
          but SM08[27..34] = current.  Why?
       -> in full data epoch, next SM07.seq = current + 1, SM08[27..34] also =+1.  Match.
       Conclusion: H10 wrong (4 SMs case breaks it).

  H11: 4 SMs epoch SM07.seq actually does NOT advance to next epoch.
       i.e. all 4 SMs epochs use same seq, and seq advances only at full data epoch.

  H12: SM08[27..34] encodes "epoch type" flag (0=clock-only, 1=full)
       but we see EVERY 256 values of SM07.seq in 8567 frames, so it's a real counter.

  H13: SM08 carries metadata about WHICH SMs were included via the
       bit pattern 0x102010, which is positional bit field (bit 67, 74, 83 = 1).

We'll directly check H11 by looking at the seq sequence vs epoch type.
"""
import os
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RTCM = os.path.join(ROOT, 'ssr_raw_data_20260510.rtcm3')
CRC24Q_POLY = 0x1864CFB
FRAME_HDR = 24

def crc24q(buf):
    crc = 0
    for b in buf:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= CRC24Q_POLY
        crc &= 0xFFFFFF
    return crc

def getbitu(buff, pos, ln):
    v = 0
    for i in range(pos, pos + ln):
        v = (v << 1) | ((buff[i >> 3] >> (7 - (i & 7))) & 1)
    return v

def iter_frames(path):
    with open(path, 'rb') as f: data = f.read()
    i, n = 0, len(data)
    while i < n:
        if data[i] != 0xD3: i += 1; continue
        if i + 3 > n: break
        ln = ((data[i+1] & 0x03) << 8) | data[i+2]
        L = 3 + ln + 3
        if i + L > n: break
        payload = data[i:i+3+ln]
        crc_bytes = data[i+3+ln:i+L]
        crc_recv = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]
        if crc_recv != crc24q(payload): i += 1; continue
        yield ln, data[i:i+L]
        i += L

# Collect epoch records ------------------------------------------------------
epochs = []   # list of dict per epoch
cur = None
for ln, fr in iter_frames(RTCM):
    if getbitu(fr, FRAME_HDR, 12) != 4090: continue
    mNo = getbitu(fr, FRAME_HDR + 16, 8)
    if mNo == 7:
        cur = {
            'sm07_seq': getbitu(fr, FRAME_HDR + 27, 8),
            'sm07_tow': getbitu(fr, FRAME_HDR + 51, 20),
            'sm07_week': getbitu(fr, FRAME_HDR + 38, 13),
            'inter_types': [],
        }
    elif mNo == 8 and cur is not None:
        cur['sm08_seq8'] = getbitu(fr, FRAME_HDR + 27, 8)
        cur['sm08_tow']  = getbitu(fr, FRAME_HDR + 35, 20)
        cur['sm08_b54_67'] = getbitu(fr, FRAME_HDR + 54, 13)
        cur['sm08_tail'] = getbitu(fr, FRAME_HDR + 64, 24)
        cur['sm_count']  = len(cur['inter_types'])
        cur['sm06_cnt']  = sum(1 for m in cur['inter_types'] if m == 6)
        cur['sm01_cnt']  = sum(1 for m in cur['inter_types'] if m == 1)
        epochs.append(cur); cur = None
    elif 1 <= mNo <= 6 and cur is not None:
        cur['inter_types'].append(mNo)

print(f"Total epochs: {len(epochs)}")
print()

# -------------------------------------------------------------------------
# H11: does SM07.seq advance every epoch? Check (epoch[i+1].seq - epoch[i].seq) % 256
print(f"=== H11: SM07.seq increment between consecutive epochs ===")
deltas_by_type_curr = defaultdict(Counter)   # keyed by current epoch type
deltas_overall = Counter()
for i in range(len(epochs) - 1):
    d = (epochs[i+1]['sm07_seq'] - epochs[i]['sm07_seq']) % 256
    deltas_overall[d] += 1
    deltas_by_type_curr[epochs[i]['sm_count']][d] += 1

print(f"  Overall (current -> next SM07.seq) delta distribution:")
for d, c in deltas_overall.most_common(5):
    print(f"     d={d}: {c}")
print()
print(f"  Delta by CURRENT epoch SM count:")
for k in sorted(deltas_by_type_curr.keys()):
    print(f"     current_cnt={k}: {dict(deltas_by_type_curr[k].most_common(5))}")
print()

# -------------------------------------------------------------------------
# H10: does SM08[27..34] match NEXT epoch's SM07.seq?
print(f"=== H10: SM08[27..34] vs NEXT SM07.seq ===")
matches = defaultdict(int); total = defaultdict(int)
for i in range(len(epochs) - 1):
    cur_e = epochs[i]; nxt = epochs[i+1]
    matched = (cur_e['sm08_seq8'] == nxt['sm07_seq'])
    matches[cur_e['sm_count']] += int(matched)
    total[cur_e['sm_count']] += 1
for k in sorted(total.keys()):
    print(f"  current_cnt={k}: {matches[k]}/{total[k]} epochs where SM08[27..34] = NEXT.SM07.seq")
print()

# -------------------------------------------------------------------------
# H13: Search SM08 bits for SM06 count (4/5/6/7) — different from total count
print(f"=== H13: Does SM08 encode SM06 count anywhere? ===")
sm06_cnts = [e['sm06_cnt'] for e in epochs]
print(f"  SM06 count distribution: {Counter(sm06_cnts)}")

# For every bit position and reasonable width, check if it correlates with sm06_cnt
candidates_exact = []   # exact match
candidates_perm = []    # one-to-one mapping
for start in range(0, 88):
    for width in (2, 3, 4, 5, 6, 7, 8):
        if start + width > 88: break
        vals = [getbitu(_fr := frame_index_for_sm08(epochs, i), FRAME_HDR + start, width)  # placeholder
                if False else 0
                for i in range(len(epochs))]
print(f"  (skipped - need direct SM08 frame access)")
print()

# Direct version: re-iterate file to capture SM08 frames
sm08_records = []
cur_pair_idx = 0
in_pair = False
for ln, fr in iter_frames(RTCM):
    if getbitu(fr, FRAME_HDR, 12) != 4090: continue
    mNo = getbitu(fr, FRAME_HDR + 16, 8)
    if mNo == 7: in_pair = True
    elif mNo == 8 and in_pair:
        sm08_records.append(fr); in_pair = False

if len(sm08_records) == len(epochs):
    print(f"  matched {len(sm08_records)} SM08 frames with {len(epochs)} epochs")
    sm06_cnts = [e['sm06_cnt'] for e in epochs]
    print(f"  Scanning SM08 bit fields for SM06 count correlation...")
    hits = []
    for start in range(0, 88):
        for width in (2, 3, 4, 5, 6, 7, 8, 12):
            if start + width > 88: break
            vals = [getbitu(sm08_records[i], FRAME_HDR + start, width) for i in range(len(epochs))]
            if len(set(vals)) == 1: continue
            # Exact match with SM06 count
            if all(v == sm06_cnts[i] for i, v in enumerate(vals)):
                hits.append((start, width, 'exact'))
            # 1-to-1 mapping
            else:
                mapping = {}
                consistent = True
                for v, c in zip(vals, sm06_cnts):
                    if v in mapping:
                        if mapping[v] != c: consistent = False; break
                    else:
                        mapping[v] = c
                if consistent and len(mapping) > 1:
                    hits.append((start, width, '1-to-1', mapping))
    if hits:
        for h in hits[:10]:
            print(f"     {h}")
    else:
        print(f"     no fields correlate with SM06 count")
print()

# -------------------------------------------------------------------------
# Q9: Search SM08 bits for TOTAL SM count (4/16/17/18/19)
print(f"=== Q9: Does SM08 encode TOTAL SM count? ===")
sm_counts = [e['sm_count'] for e in epochs]
hits = []
for start in range(0, 88):
    for width in (2, 3, 4, 5, 6, 7, 8, 12):
        if start + width > 88: break
        vals = [getbitu(sm08_records[i], FRAME_HDR + start, width) for i in range(len(epochs))]
        if len(set(vals)) == 1: continue
        mapping = {}
        consistent = True
        for v, c in zip(vals, sm_counts):
            if v in mapping:
                if mapping[v] != c: consistent = False; break
            else:
                mapping[v] = c
        if consistent and len(mapping) > 1:
            hits.append((start, width, mapping))
if hits:
    for h in hits[:10]:
        print(f"     {h}")
else:
    print(f"     no fields correlate with TOTAL SM count")
print()
