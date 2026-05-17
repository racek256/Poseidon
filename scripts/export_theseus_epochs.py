#!/usr/bin/env python3
"""Export each epoch checkpoint as Theseus-{n}e GGUF."""

import os, shutil, subprocess, sys, json
from pathlib import Path

os.environ.setdefault("UNSLOTH_RETURN_LOGITS", "1")
os.environ["UNSLOTH_COMPILE_DISABLE"] = "1"
os.environ["UNSLOTH_FUSED_CE_COMPILE_DISABLE"] = "1"
import unsloth
import torch
from unsloth import FastLanguageModel
from peft import PeftModel

base_model = "google/gemma-3-1b-it"
max_len = 768
llama_cpp = Path("external/llama.cpp/convert_hf_to_gguf.py")
merged_base = Path("models/finetuned/merged")

epoches = [
    ("checkpoint-315", "1e"),
    ("checkpoint-630", "2e"),
    ("checkpoint-945", "3e"),
]

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Device: {device}")
if device == "cuda":
    print(f"GPU: {torch.cuda.get_device_name()}")

for ckpt_name, suffix in epoches:
    ckpt_path = Path(f"models/finetuned/checkpoints/{ckpt_name}")
    if not ckpt_path.exists():
        print(f"Skipping {ckpt_name} (not found)")
        continue

    gguf_name = f"Theseus-{suffix}-q4_k_m.gguf"
    gguf_bf16 = Path(f"models/Theseus-{suffix}-bf16.gguf")
    gguf_q4 = Path(f"models/{gguf_name}")

    if gguf_q4.exists():
        print(f"SKIP {gguf_name} already exists")
        continue

    print(f"\n=== Exporting {ckpt_name} → {gguf_name} ===")

    print("Loading base model (bf16)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model,
        max_seq_length=max_len,
        dtype=torch.bfloat16,
        load_in_4bit=False,
        load_in_8bit=False,
        device_map="auto",
        fast_inference=False,
    )

    print(f"Loading adapter: {ckpt_path}")
    model = PeftModel.from_pretrained(model, str(ckpt_path))

    print("Merging adapter to bf16...")
    merged = model.merge_and_unload()

    # Fix config (remove quantization config)
    merged.config.quant_method = None
    merged.config.quantization_config = None

    merged_dir = merged_base / ckpt_name
    if merged_dir.exists():
        shutil.rmtree(str(merged_dir))
    merged_dir.mkdir(parents=True, exist_ok=True)

    print("Saving full model...")
    state_dict = {k: v.clone().contiguous() for k, v in merged.state_dict().items()}
    from safetensors.torch import save_file as safe_save
    safe_save(state_dict, str(merged_dir / "model.safetensors"))

    # Fix config.json to remove quantization
    merged.config.save_pretrained(str(merged_dir))
    saved = json.load(open(str(merged_dir / "config.json")))
    if "quantization_config" in saved:
        del saved["quantization_config"]
    json.dump(saved, open(str(merged_dir / "config.json"), "w"), indent=2)

    tokenizer.save_pretrained(str(merged_dir))

    print("Converting to GGUF (bf16)...")
    result = subprocess.run([
        sys.executable, str(llama_cpp),
        str(merged_dir), "--outtype", "bf16",
        "--outfile", str(gguf_bf16),
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"GGUF conversion failed: {result.stderr}")
        continue

    print(f"Quantizing to Q4_K_M...")
    subprocess.run([
        "external/llama.cpp/build/bin/llama-quantize",
        str(gguf_bf16), str(gguf_q4), "q4_k_m"
    ], check=True)

    gguf_bf16.unlink()
    print(f"DONE: {gguf_q4} ({gguf_q4.stat().st_size / 1e6:.1f} MB)")

    # Free up VRAM
    del model, merged, state_dict
    torch.cuda.empty_cache()

print("\nAll done!")
