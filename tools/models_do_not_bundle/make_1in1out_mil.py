#!/usr/bin/env python3
"""Live P044 triad = compiler MobileNet MIL with dummy extras stripped.

ane_mil_mobilenet_224/model.mil is coremlc output with x_1 + x_extra_1..253.
The body only uses x_1. Strip extras, keep real weights1.bin, t8101 options.
Not 254. Not evaluate.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "ane_mil_mobilenet_224"
LIVE = Path(__file__).resolve().parents[2] / "P007OpenOnly" / "model"
MIRROR = ROOT / "ane_mil_1in1out"

OPTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>t8101</key>
	<dict>
		<key>EnableLowEffortCPAllocation</key>
		<true/>
	</dict>
</dict>
</plist>
"""


def strip_extras(t: str) -> str:
    i = t.find("func main_ane")
    j = t.find(") {", i)
    sig = t[i:j]
    marker = "> x_1, "
    k = sig.find(marker)
    if i < 0 or j < 0 or k < 0:
        raise SystemExit("cannot find main_ane / x_1 extras")
    new_sig = sig[: k + len("> x_1")]
    out = t[:i] + new_sig + t[j:]
    if "x_extra" in out:
        raise SystemExit("extras remain")
    return out


def main() -> None:
    mil = strip_extras((SRC / "model.mil").read_text())
    w = (SRC / "weights1.bin").read_bytes()
    for dest in (LIVE, MIRROR):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "model.mil").write_text(mil)
        (dest / "options.plist").write_text(OPTS)
        (dest / "weights1.bin").write_bytes(w)
        print(
            "wrote",
            dest,
            "mil",
            (dest / "model.mil").stat().st_size,
            "weights",
            (dest / "weights1.bin").stat().st_size,
        )


if __name__ == "__main__":
    main()
