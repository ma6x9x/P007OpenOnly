#!/usr/bin/env python3
"""Build the P007 1-in/1-out CoreML model — the one that helps the KRW path.

This is NOT 254 inputs and NOT the 43748 OOB trigger.
43748 needs ProgramSendRequest IOSurface counts >0x80 after DirectPath open.
This model is the legal CoreML→ANE ABI (buttons 72 / P034 occupancy).

  /tmp/p007ct/bin/python tools/make_simple_1in1out.py
"""
from pathlib import Path

from coremltools.models.datatypes import Array
from coremltools.models.neural_network import NeuralNetworkBuilder
from coremltools.proto import FeatureTypes_pb2 as ft

OUT = Path(__file__).resolve().parent / "models_do_not_bundle" / "simple_1in1out.mlmodel"


def main():
    builder = NeuralNetworkBuilder(
        input_features=[("input", Array(1, 1))],
        output_features=[("output", Array(1, 1))],
        disable_rank5_shape_mapping=True,
    )
    builder.add_elementwise(
        name="mul2",
        input_names=["input"],
        output_name="output",
        mode="MULTIPLY",
        alpha=2.0,
    )
    spec = builder.spec
    # FLOAT32 matches P033 MLMultiArrayDataTypeFloat32
    for t in list(spec.description.input) + list(spec.description.output):
        t.type.multiArrayType.dataType = ft.ArrayFeatureType.FLOAT32
    spec.description.metadata.shortDescription = (
        "P007 1-in/1-out ABI. Legal ANE/CoreML open path. Not 254. Not 43748 OOB."
    )
    if spec.specificationVersion < 4:
        spec.specificationVersion = 4
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(spec.SerializeToString())
    print("wrote", OUT, "bytes", OUT.stat().st_size)


if __name__ == "__main__":
    main()
