#!/usr/bin/env python3
"""Emit the P044 _ANEModel MIL triad: 254x[1,1,1,1] fp32 add-chain.

This is the graph in many_254in1out.mlmodel (in_0..in_253 + add chain),
rewritten as ANE MIL. The desktop .mlmodel is rank-2 Array(1,1) and
coremlc rejects it. This MIL uses 4-D tensor_buffers like the working
ANE dialect in the old MobileNet dump.

Not evaluate. Not 43748 fire. Load/compile asset only.
"""
from pathlib import Path

N = 254
SHAPE = "[1, 1, 1, 1]"
STRIDES = "[1, 1, 1, 1]"
ILEAVE = "[1, 1, 1, 1]"
TB = (
    "tensor_buffer<fp32, shape="
    + SHAPE
    + ", strides="
    + STRIDES
    + ", interleave_factors="
    + ILEAVE
    + ">"
)
TT = "tensor<fp32, " + SHAPE + ">"

ROOT = Path(__file__).resolve().parent
LIVE = Path(__file__).resolve().parents[2] / "P007OpenOnly" / "model"
MIRROR = ROOT / "ane_mil"


def mil_text() -> str:
    args = ",\n".join(f"        {TB} in_{i}" for i in range(N))
    lines = []
    mid = 0
    for i in range(N):
        lines.append(
            f"        {TT} t_{i} = tensor_buffer_to_tensor<ios17>"
            f"(input = in_{i})[milId = uint64({mid})];"
        )
        mid += 1
    lines.append(
        f"        {TT} acc_1 = add(x = t_0, y = t_1)"
        f"[milId = uint64({mid}), name = string(\"add_1\")];"
    )
    mid += 1
    for i in range(2, N):
        lines.append(
            f"        {TT} acc_{i} = add(x = acc_{i-1}, y = t_{i})"
            f"[milId = uint64({mid}), name = string(\"add_{i}\")];"
        )
        mid += 1
    lines.append(
        f"        {TB} output = tensor_to_tensor_buffer<ios17>("
        f"input = acc_{N-1}, "
        f"interleave_factors = tensor<uint8, [4]>({ILEAVE}), "
        f"strides = tensor<int64, [4]>({STRIDES}))"
        f"[milId = uint64({mid})];"
    )
    body = "\n".join(lines)
    build = (
        '[buildInfo = dict<string, string>({{'
        '"coremlc-component-MIL", "3520.4.1"}, '
        '{"coremlc-version", "3520.5.1"}, '
        '{"source", "many_254in1out addchain"}})]'
    )
    return (
        "program(1.3)\n"
        f"{build}\n"
        "{\n"
        "    func main_ane<ios15>(\n"
        f"{args}\n"
        "    ) {\n"
        f"{body}\n"
        "    } -> (output);\n"
        "}\n"
    )


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


def main() -> None:
    mil = mil_text()
    assert "in_0" in mil and "in_253" in mil
    assert "in_254" not in mil
    assert "acc_253" in mil
    assert "BLOBFILE" not in mil
    assert "224, 224" not in mil
    weights = bytes.fromhex("4f00000002000000") + bytes(56)
    for dest in (LIVE, MIRROR):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "model.mil").write_text(mil)
        (dest / "options.plist").write_text(OPTS)
        (dest / "weights1.bin").write_bytes(weights)
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
