#!/usr/bin/env python3
"""Export finetuned adapter as GGUF named Theseus, using local llama.cpp converter."""

import os, shutil, subprocess, sys
from pathlib import Path

os.environ.setdefault("UNSLOTH_RETURN_LOGITS", "1")
os.environ["UNSLOTH_COMPILE_DISABLE"] = "1"
os.environ["UNSLOTH_FUSED_CE_COMPILE_DISABLE"] = "1"
import unsloth
import torch
from unsloth import FastLanguageModel
from peft import PeftModel

base_model = "google/gemma-3-1b-it"
adapter_path = "models/finetuned/adapter"
max_len = 768
merged_dir = Path("models/finetuned/merged")
gguf_bf16 = Path("models/Theseus-bf16.gguf")
gguf_q4 = Path("models/Theseus-q4_k_m.gguf")
llama_cpp = Path("external/llama.cpp/convert_hf_to_gguf.py")

if not llama_cpp.exists():
    print(f"ERROR: {llama_cpp} not found")
    sys.exit(1)

print(f"Loading base model (bf16): {base_model}")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=base_model,
    max_seq_length=max_len,
    dtype=torch.bfloat16,
    load_in_4bit=False,
    load_in_8bit=False,
    device_map="auto",
    fast_inference=False,
)

print(f"Loading adapter: {adapter_path}")
model = PeftModel.from_pretrained(model, adapter_path)

print("Merging adapter and converting to bf16...")
merged = model.merge_and_unload()

merged_dir.mkdir(parents=True, exist_ok=True)
print(f"Saving full model to {merged_dir}")
# Handle tied weights: save independently
state_dict = {k: v.clone().contiguous() for k, v in merged.state_dict().items()}
from safetensors.torch import save_file as safe_save
safe_save(state_dict, str(merged_dir / "model.safetensors"))
# Save config from loaded model (already cached)
config = merged.config
config.quant_method = None
config.quantization_config = None
if hasattr(config, '_quantization_config'):
    config._quantization_config = None
config.save_pretrained(str(merged_dir))
tokenizer.save_pretrained(str(merged_dir))
# Double-check the saved config doesn't have quantization
import json
saved = json.load(open(str(merged_dir / "config.json")))
if "quantization_config" in saved:
    del saved["quantization_config"]
    json.dump(saved, open(str(merged_dir / "config.json"), "w"))
print("Full model saved")

print("Converting to GGUF (bf16)...")
result = subprocess.run([
    sys.executable, str(llama_cpp),
    str(merged_dir), "--outtype", "bf16",
    "--outfile", str(gguf_bf16),
], capture_output=True, text=True)
if result.returncode != 0:
    print(f"GGUF conversion failed: {result.stderr}")
    sys.exit(1)
print(f"GGUF exported: {gguf_bf16}")

print("Quantizing to Q4_K_M...")
subprocess.run([
    "external/llama.cpp/build/bin/llama-quantize",
    str(gguf_bf16), str(gguf_q4), "q4_k_m"
], check=True)

print(f"Done! Model size: {gguf_q4.stat().st_size / 1e6:.1f} MB")
