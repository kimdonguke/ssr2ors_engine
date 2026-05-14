"""
java_mirror.py - line-by-line Python port of SsrgDecoder.java
   used to cross-verify the C++ SSR-G decoder against the Java reference.

Outputs the same per-message text format as main.cpp::dumpSsrg(),
allowing direct diff.
"""

import sys
import struct

# ---- CRC24Q (RTKLIB-style table, identical to Util.java) -----------------
def crc24q(buf):
    TABLE = [
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
        0x42FA2F,0xC4B6D4,0xC82F22,0x4E63D9,0xD11CCE,0x575035,0x5BC9C3,0xDD8538,
    ]
    crc = 0
    for b in buf:
        crc = TABLE[((crc >> 16) ^ b) & 0xFF] ^ ((crc << 8) & 0xFFFFFF)
    return crc

# ---- Java's Util.readUBits / readBits (operating on a "01" string) -------
def readUBits(buf, start, length):
    return int(buf[start:start + length], 2)

def readBits(buf, start, length):
    if length == 1:
        return int(buf[start:start + 1], 2)
    signBit = int(buf[start:start + 1], 2)
    value   = int(buf[start + 1:start + length], 2)
    if length == 32:
        return value + (signBit << (length - 1))
    return value - (signBit << (length - 1))

def bytes_to_bitstr(b):
    return "".join(f"{x:08b}" for x in b)

def prn_prefix(g):
    return {0: 100, 1: 300, 2: 400, 3: 600, 4: 500, 5: 200}.get(g, 0)

# ---- parsers (line-by-line Java port) -------------------------------------
def parseSM001(buf, gs, ver):
    out = []
    gnss = readUBits(buf, 57, 4)
    refd = readUBits(buf, 61, 1)  # noqa: F841
    noSat = readUBits(buf, 62, 6)
    base = prn_prefix(gnss)
    size = 8 if ver == 0 else 11
    pos = 68
    for _ in range(noSat):
        prn = base + readUBits(buf, pos, 6)
        iod = readUBits(buf, pos + 6, size)
        rad = readBits(buf, pos + 6 + size, 22) * 1e-4
        alt = readBits(buf, pos + 28 + size, 20) * 4e-4
        crt = readBits(buf, pos + 48 + size, 20) * 4e-4
        out.append(("ORB", gs, prn, iod, rad, alt, crt))
        pos += 68 + size
    return out

def parseSM002(buf, gs, ver):
    out = []
    gnss = readUBits(buf, 57, 4)
    noSat = readUBits(buf, 61, 6)
    base = prn_prefix(gnss)
    pos = 67
    for _ in range(noSat):
        prn = base + readUBits(buf, pos, 6)
        c0 = readBits(buf, pos + 6, 22) * 1e-4
        c1 = readBits(buf, pos + 28, 21) * 1e-6
        c2 = readBits(buf, pos + 49, 27) * 2e-8
        out.append(("CLK", gs, prn, c0, c1, c2))
        pos += 76
    return out

def parseSM003(buf, gs, ver):
    out = []
    gnss = readUBits(buf, 57, 4)
    noSat = readUBits(buf, 61, 6)
    base = prn_prefix(gnss)
    pos = 67
    for _ in range(noSat):
        prn = base + readUBits(buf, pos, 6)
        if ver == 0:
            c1 = readBits(buf, pos + 6, 14) * 0.01
            p2 = readBits(buf, pos + 20, 14) * 0.01
            l1 = readBits(buf, pos + 34, 22) * 1e-4
            l2 = readBits(buf, pos + 56, 22) * 1e-4
            out.append(("BIAS", gs, prn, 0, c1, l1))
            out.append(("BIAS", gs, prn, 11, p2, l2))
            pos += 78
        else:
            noSigs = readUBits(buf, pos + 6, 4)
            pos += 10 if ver == 1 else 11
            sigSz = 45 if ver <= 2 else 55
            for _ in range(noSigs):
                sid = readUBits(buf, pos, 5)
                c = readBits(buf, pos + 5, 14) * 0.01
                p = readBits(buf, pos + 19, 22) * 1e-4
                out.append(("BIAS", gs, prn, sid, c, p))
                pos += sigSz
    return out

def parseSM006(buf, gs, ver):
    out = []
    gnss = readUBits(buf, 57, 4)
    noGP = readUBits(buf, 61, 6)
    base = prn_prefix(gnss)
    pos = 67
    for _ in range(noGP):
        lat = readBits(buf, pos + 2, 28) * 1e-6
        lon = readBits(buf, pos + 30, 29) * 1e-6
        hgt = readBits(buf, pos + 59, 24) * 1e-3
        if ver <= 1:
            tr = readBits(buf, pos + 83, 16) * 1e-4
            tw = readBits(buf, pos + 99, 14) * 1e-4
            noSat = readUBits(buf, pos + 113, 6)
            pos += 119
        else:
            tr = readBits(buf, pos + 83, 18) * 1e-4
            tw = readBits(buf, pos + 101, 14) * 1e-4
            noSat = readUBits(buf, pos + 115, 6)
            pos += 121
        out.append(("TROP", gs, lat, lon, hgt, tr, tw))
        for _ in range(noSat):
            prn = base + readUBits(buf, pos, 6)
            stec = readBits(buf, pos + 6, 30) * 1e-5
            out.append(("STEC", gs, lat, lon, hgt, prn, stec))
            pos += 36
    return out

# ---- frame splitter & driver ---------------------------------------------
def main(path, out_path):
    with open(path, "rb") as f:
        data = f.read()
    out = open(out_path, "w") if out_path != "-" else sys.stdout
    n_ssrg = 0
    counts = {}
    pos = 0
    last_sm07_seq = 0   # tracks the most recent SM07.seq for typeFlag derivation
    while pos < len(data):
        # find 0xD3
        while pos < len(data) and data[pos] != 0xD3:
            pos += 1
        if pos + 3 > len(data):
            break
        length = ((data[pos + 1] & 0x03) << 8) | data[pos + 2]
        end = pos + 3 + length
        if end + 3 > len(data):
            break
        payload = data[pos + 3:end]
        crc_want = (data[end] << 16) | (data[end + 1] << 8) | data[end + 2]
        if crc24q(data[pos:end]) != crc_want:
            pos += 1
            continue
        # decode header from payload bit string
        buf = bytes_to_bitstr(payload)
        no = readUBits(buf, 0, 12)
        if no == 4090:
            mNo = readUBits(buf, 16, 8)
            # SM07 / SM08 have a DIFFERENT header layout (no gs at 27..46);
            # handle them before reading the SM01-006 header.
            if mNo == 7:
                ver_s = readUBits(buf, 24, 3)
                seq_s = readUBits(buf, 27, 8)
                week  = readUBits(buf, 38, 13)
                tow   = readUBits(buf, 51, 20)
                last_sm07_seq = seq_s
                out.write(f"MT4090 mNo=7 START  ver={ver_s} seq={seq_s:3d} week={week} tow={tow}\n")
                counts[7] = counts.get(7, 0) + 1
                n_ssrg += 1
                pos = end + 3
                continue
            if mNo == 8:
                ver_e = readUBits(buf, 24, 3)
                seq_e = readUBits(buf, 27, 8)
                flag  = (seq_e - last_sm07_seq) & 0xFF
                tow_e = readUBits(buf, 35, 20)
                tail  = readUBits(buf, 64, 24)
                out.write(f"MT4090 mNo=8 END    ver={ver_e} seq={seq_e:3d} flag={flag} tow={tow_e}  tail=0x{tail:06X}\n")
                counts[8] = counts.get(8, 0) + 1
                n_ssrg += 1
                pos = end + 3
                continue

            ver = readUBits(buf, 24, 3)
            gs  = readUBits(buf, 27, 20)
            ui  = readUBits(buf, 47, 4)
            mmi = readUBits(buf, 51, 1)
            uic = readUBits(buf, 52, 1)
            gnss = readUBits(buf, 57, 4) if mNo != 4 else 0
            refd = readUBits(buf, 61, 1) if mNo == 1 else 0
            if mNo == 1:
                recs = parseSM001(buf, gs, ver)
            elif mNo == 2:
                recs = parseSM002(buf, gs, ver)
            elif mNo == 3:
                recs = parseSM003(buf, gs, ver)
            elif mNo == 6:
                recs = parseSM006(buf, gs, ver)
            else:
                pos = end + 3
                continue

            counts[mNo] = counts.get(mNo, 0) + 1
            n_ssrg += 1

            # bucket records by tag (matches C++ vector order: orb,clk,bias,trop,stec)
            buckets = {"ORB": [], "CLK": [], "BIAS": [], "TROP": [], "STEC": []}
            for r in recs:
                buckets[r[0]].append(r)
            ordered = buckets["ORB"] + buckets["CLK"] + buckets["BIAS"] + buckets["TROP"] + buckets["STEC"]
            out.write(
                f"MT4090 mNo={mNo} ver={ver} gs={gs} gnss={gnss} refd={refd} "
                f"mmi={mmi} uic={uic} ui={ui} "
                f"noOrb={len(buckets['ORB'])} noClk={len(buckets['CLK'])} "
                f"noBias={len(buckets['BIAS'])} noTrop={len(buckets['TROP'])} "
                f"noStec={len(buckets['STEC'])}\n"
            )
            for r in ordered:
                tag = r[0]
                if tag == "ORB":
                    _, gs_, prn, iod, rad, alt, crt = r
                    out.write(f"  ORB gs={gs_} prn={prn:3d} iod={iod:4d} rad={rad:+.4f} alt={alt:+.4f} crt={crt:+.4f}\n")
                elif tag == "CLK":
                    _, gs_, prn, c0, c1, c2 = r
                    out.write(f"  CLK gs={gs_} prn={prn:3d} c0={c0:+.4f} c1={c1:+.6f} c2={c2:+.10f}\n")
                elif tag == "BIAS":
                    _, gs_, prn, sid, c, p = r
                    out.write(f"  BIAS gs={gs_} prn={prn:3d} sig={sid:2d} code={c:+.4f} phase={p:+.4f}\n")
                elif tag == "TROP":
                    _, gs_, lat, lon, hgt, tr, tw = r
                    out.write(f"  TROP gs={gs_} lat={lat:+10.6f} lon={lon:+11.6f} hgt={hgt:+9.3f} ztd={tr:+.4f} zwd={tw:+.4f}\n")
                elif tag == "STEC":
                    _, gs_, lat, lon, hgt, prn, stec = r
                    out.write(f"  STEC gs={gs_} lat={lat:+10.6f} lon={lon:+11.6f} hgt={hgt:+9.3f} prn={prn:3d} stec={stec:+.5f}\n")
        pos = end + 3
    sys.stderr.write(f"java-mirror: {n_ssrg} SSR-G messages decoded.\n")
    for m, c in sorted(counts.items()):
        sys.stderr.write(f"  SM{m:03d} : {c}\n")
    if out is not sys.stdout:
        out.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python java_mirror.py <input> <output|->")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
