P007 model assets — keep this folder OUT of the live target
===========================================================

IN APP (synced):
  P007OpenOnly/simple_1in1out.mlmodelc/     CoreML 1-in/1-out (P033)
  P007OpenOnly/model/{model.mil,options.plist,weights1.bin}
                                            _ANEModel MIL triad (P044)
                                            1-in/1-out: input+input (×2)
                                            options.plist key t8101 (A14)
                                            weights1.bin is a 64-byte stub
  P007OpenOnly/XVRC27_254in_1out_addchain.mlmodelc/
                                            CoreML espresso — NOT what _ANEModel loads

The folder named `model:` at the project ROOT is NOT in the IPA.
Do not use it. Live copy is P007OpenOnly/model/.

DO NOT put in the live target:
  *.mlmodel / *.mlpackage                   coremlc breaks the build
  tools/models_do_not_bundle/ane_mil/       mirror of the live triad
  poc-ane-ui/                               their UIKit PoC sources, not SwiftPeek

_ANEModel wants one directory with ALL THREE:
  Live P044 triad is 1-in/1-out (make_1in1out_mil.py → P007OpenOnly/model/).
  ane_mil_1in1out/             mirror of the live 1-in triad
  ane_mil/                     254 add-chain (NOT in the live target)
  ane_mil_mobilenet_224/       MobileNet 224 dump (NOT in the live target)

MobileNet 224×224×254 dump kept at:
  ane_mil_mobilenet_224/       (why ANECCompile FAILED on A14)

many_254in1out.mlmodel is CoreML rank-2 Array(1,1) — coremlc rejects it
("dimension 1 or 3"). Do NOT put it in the live target. The MIL triad
is that graph, rewritten as ANE tensor_buffers.

Key: XVRC27/mach_msg_min/model.anehash
Factory: +modelAtURLWithSourceURL:sourceURL:key:cacheURLIdentifier:

CoreML espresso is a different file:
  XVRC27_254in_1out_addchain.mlmodelc       NOT what _ANEModel loads

ViewController.m does not help P007. It is their UI. Load logic is already
in P044 (factory + key). poc-ane-ui/ is reference only.

Regenerate simple_1in1out.mlmodelc:
  DEVELOPER_DIR="/Users/kolby/Downloads/Xcode.app/Contents/Developer" \
    coremlc compile tools/models_do_not_bundle/simple_1in1out.mlmodel /tmp/p007_mlc
  rm -rf P007OpenOnly/simple_1in1out.mlmodelc
  cp -R /tmp/p007_mlc/simple_1in1out.mlmodelc P007OpenOnly/
