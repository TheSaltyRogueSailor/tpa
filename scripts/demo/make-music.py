#!/usr/bin/env python3
"""Synthesize an original background track for the TPA demo video (numpy only).

Timeline mirrors animated-page.html: INTRO=4200, CTRL=9200 (APPROVED stamp at +5400),
11 attacks of ATT=5600 (DENIED stamp at +3000), END=7500 -> TOTAL 82.5 s.
Tempo 107.14 BPM so one beat = 0.56 s and every attack segment = exactly 10 beats.
Output: 48 kHz stereo 16-bit WAV (pre-loudnorm). Usage: make-music.py out.wav
"""
import sys, wave
import numpy as np

SR = 48000
INTRO, CTRL, ATT, END, N_ATT = 4.2, 9.2, 5.6, 7.5, 11
TOTAL = INTRO + CTRL + N_ATT * ATT + END          # 82.5
APPROVED_T = INTRO + 5.4                          # 9.6
ATT0 = INTRO + CTRL                               # 13.4
DENIED_T = [ATT0 + k * ATT + 3.0 for k in range(N_ATT)]
END_T = ATT0 + N_ATT * ATT                        # 75.0
BEAT = 0.56
N = int(round(TOTAL * SR))
t = np.arange(N) / SR
rng = np.random.default_rng(7)

def hz(m): return 440.0 * 2 ** ((m - 69) / 12)
def env_adsr(n, a, d, s, r, sus_len):
    a, d, r = int(a*SR), int(d*SR), int(r*SR); sl = max(int(sus_len*SR) - a - d, 0)
    e = np.concatenate([np.linspace(0, 1, a, endpoint=False), np.linspace(1, s, d, endpoint=False),
                        np.full(sl, s), np.linspace(s, 0, r)])
    return e[:n] if len(e) >= n else np.pad(e, (0, n - len(e)))
def add(buf, start, sig):
    i = int(round(start * SR));
    if i >= len(buf): return
    j = min(len(buf), i + len(sig)); buf[i:j] += sig[:j - i]
def lowpass_fft(x, fc, slope=2.0):
    X = np.fft.rfft(x); f = np.fft.rfftfreq(len(x), 1/SR)
    X *= 1 / np.sqrt(1 + (f / fc) ** (2 * slope)); return np.fft.irfft(X, len(x))
def soft_saw(f, dur, nh=10, detune=0.0, phase=0.0):
    tt = np.arange(int(dur*SR)) / SR; y = np.zeros_like(tt)
    for h in range(1, nh + 1):
        if f*h > 9000: break
        y += np.sin(2*np.pi*f*h*(1+detune)*tt + phase*h) / h * (0.85 ** h)
    return y

# chord sections (MIDI). Key A minor; control lifts to C major; end resolves to A major-ish (Fmaj7 -> Cmaj9 -> A sus/maj)
Am, F, C, G, Em = [57,60,64,67], [53,57,60,64], [48,55,60,64], [55,59,62,67], [52,55,59,64]
sections = [(0.0, INTRO, Am, 45)]
sections += [(INTRO, APPROVED_T - INTRO, F, 41), (APPROVED_T, ATT0 - APPROVED_T, [48,55,60,64,71], 48)]  # Cmaj7 lift on APPROVED
prog = [Am, F, C, G]
for k in range(N_ATT): sections.append((ATT0 + k*ATT, ATT, prog[k % 4], [45, 41, 48, 43][k % 4]))
sections.append((END_T, TOTAL - END_T, [53,57,60,64,67], 41))  # Fmaj9 then resolve below

pad_L = np.zeros(N); pad_R = np.zeros(N); bass = np.zeros(N)
for (st, du, chord, root) in sections:
    if st >= END_T:  # end card: Fmaj9 (2 s) -> Cmaj9 (rest) resolve
        for (s2, d2, ch2, r2) in [(st, 2.24, chord, 41), (st + 2.24, TOTAL - st - 2.24, [48,55,60,64,67,74], 36)]:
            for i, m in enumerate(ch2):
                e = env_adsr(int((d2+1.2)*SR), 0.5, 0.6, 0.8, 1.2, d2)
                add(pad_L, s2, soft_saw(hz(m), d2+1.2, detune=-0.003, phase=i) * e * 0.12)
                add(pad_R, s2, soft_saw(hz(m), d2+1.2, detune=+0.003, phase=i+1) * e * 0.12)
            e = env_adsr(int((d2+0.8)*SR), 0.3, 0.5, 0.7, 0.8, d2)
            add(bass, s2, np.sin(2*np.pi*hz(r2-12)*np.arange(int((d2+0.8)*SR))/SR) * e * 0.5)
        continue
    atk = 3.0 if st == 0 else (0.08 if st == APPROVED_T else 0.35)
    for i, m in enumerate(chord):
        e = env_adsr(int((du+0.9)*SR), atk, 0.4, 0.75, 0.9, du)
        g = 0.14 if st == APPROVED_T else 0.11
        add(pad_L, st, soft_saw(hz(m), du+0.9, detune=-0.003, phase=i) * e * g)
        add(pad_R, st, soft_saw(hz(m), du+0.9, detune=+0.003, phase=i+1) * e * g)
    if st >= INTRO:  # pulsing 8th-note bass (from INTRO onward)
        b0 = st
        nb = int(round(du / (BEAT/2)))
        for j in range(nb):
            s = b0 + j*BEAT/2
            if s >= st + du: break
            n = int(0.24*SR); tt = np.arange(n)/SR
            e = np.exp(-tt*9) * np.minimum(1, tt/0.004)
            f0 = hz(root - 12)
            sig = (np.sin(2*np.pi*f0*tt) + 0.35*np.sin(2*np.pi*2*f0*tt) + 0.12*np.sin(2*np.pi*3*f0*tt)) * e
            add(bass, s, sig * (0.42 if j % 2 == 0 else 0.30))

# APPROVED sparkle: bright arpeggio C-E-G-B-E
for i, m in enumerate([72, 76, 79, 83, 88]):
    n = int(1.4*SR); tt = np.arange(n)/SR
    sig = (np.sin(2*np.pi*hz(m)*tt) + 0.3*np.sin(2*np.pi*2*hz(m)*tt)) * np.exp(-tt*3.2) * np.minimum(1, tt/0.003)
    add(pad_L, APPROVED_T + i*0.07, sig * 0.07 * (1.0 if i % 2 else 0.6))
    add(pad_R, APPROVED_T + i*0.07, sig * 0.07 * (0.6 if i % 2 else 1.0))

# drums: soft kick on beats, hi-hat on offbeats, grid anchored at ATT0 (each attack = 10 beats)
drums = np.zeros(N); hats_L = np.zeros(N); hats_R = np.zeros(N)
def kick(gain):
    n = int(0.35*SR); tt = np.arange(n)/SR
    f = 45 + 70*np.exp(-tt*30); ph = 2*np.pi*np.cumsum(f)/SR
    return np.sin(ph) * np.exp(-tt*9) * gain
def hat(gain):
    n = int(0.06*SR); x = rng.standard_normal(n); x = np.diff(np.concatenate([[0], x]))
    return x * np.exp(-np.arange(n)/SR*70) * gain
first = ATT0 - BEAT * np.floor((ATT0 - INTRO) / BEAT)
b = first; k = 0
while b < END_T - 1e-6:
    ctrl = b < ATT0
    near_stamp = any(abs(b - d) < 0.30 for d in DENIED_T)
    if not near_stamp: add(drums, b, kick(0.55 if not ctrl else 0.40))
    hb = b + BEAT/2
    if hb < END_T:
        h = hat(0.10 if not ctrl else 0.06); add(hats_L, hb, h*0.8); add(hats_R, hb, h)
    if not ctrl and k % 2 == 1:
        h = hat(0.045); add(hats_L, b + BEAT/4, h); add(hats_R, b + 3*BEAT/4, h*0.8)
    b += BEAT; k += 1
add(drums, END_T, kick(0.5))
# intro: rising filtered noise swell into 4.2 s
n = int(INTRO*SR); sw = lowpass_fft(rng.standard_normal(n), 1800) * (np.linspace(0, 1, n) ** 2.5) * 0.05
add(hats_L, 0, sw); add(hats_R, 0, sw[::-1][::-1])

# DENIED hit: low pitch-dropping thud + short dark noise burst + tiny duck of pad
hits = np.zeros(N); duck = np.ones(N)
for d in DENIED_T:
    n = int(0.9*SR); tt = np.arange(n)/SR
    f = 38 + 55*np.exp(-tt*14); ph = 2*np.pi*np.cumsum(f)/SR
    th = np.sin(ph) * np.exp(-tt*4.5) * np.minimum(1, tt/0.002) * 0.5
    nz = lowpass_fft(rng.standard_normal(n), 400) * np.exp(-tt*18) * 0.2
    add(hits, d, th + nz)
    i = int(d*SR); m = int(0.6*SR)
    duck[i:i+m] = np.minimum(duck[i:i+m], 1 - 0.35*np.exp(-np.arange(m)/SR*6))

pad_L = lowpass_fft(pad_L, 2600) * duck; pad_R = lowpass_fft(pad_R, 2600) * duck
bass = lowpass_fft(bass, 500)
L = pad_L + bass + drums + hits + hats_L
R = pad_R + bass + drums + hits + hats_R
# master fade: 2.5 s fade out at the end, tiny fade in
fade = np.ones(N); fo = int(2.5*SR); fade[-fo:] = np.linspace(1, 0, fo) ** 1.5
fi = int(0.05*SR); fade[:fi] *= np.linspace(0, 1, fi)
L *= fade; R *= fade
peak = max(np.abs(L).max(), np.abs(R).max()); L, R = L/peak*0.7, R/peak*0.7
out = np.stack([L, R], 1); pcm = (np.clip(out, -1, 1) * 32767).astype('<i2')
with wave.open(sys.argv[1] if len(sys.argv) > 1 else 'music-raw.wav', 'wb') as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes(pcm.tobytes())
print(f"wrote {N/SR:.3f}s; APPROVED {APPROVED_T}s; DENIED {[round(x,2) for x in DENIED_T]}; END {END_T}s")
