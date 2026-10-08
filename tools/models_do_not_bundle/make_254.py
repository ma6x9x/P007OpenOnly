import coremltools as ct
from coremltools.models import datatypes
from coremltools.models.neural_network import NeuralNetworkBuilder

# Rank-2 Array(1,1) is REJECTED by coremlc:
#   "Input MLMultiArray to neural networks must have dimension 1 or 3."
# Keep this file as the original generator. Live P044 asset is MIL:
#   make_254_mil_addchain.py → P007OpenOnly/model/
# Define 254 inputs, each shape (1,1) — original (invalid for coremlc)
input_features = [(f"in_{i}", datatypes.Array(1,1)) for i in range(254)]
output_features = [("output", datatypes.Array(1,1))]

# Build a neural network that sums all 254 inputs
builder = NeuralNetworkBuilder(input_features, output_features)

# Chain additions: in_0 + in_1 -> tmp_1, tmp_1 + in_2 -> tmp_2, etc.
current_name = "in_0"
for i in range(1, 254):
    next_name = f"in_{i}"
    out_name = f"tmp_{i}" if i < 253 else "output"
    builder.add_elementwise(name=f"add_{i}", 
                            input_names=[current_name, next_name], 
                            output_name=out_name, 
                            mode="ADD")
    current_name = out_name

# Save the model
model = ct.models.MLModel(builder.spec)
model.save("many_254in1out.mlmodel")
print("done - model created!")
