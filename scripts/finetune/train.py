#!/usr/bin/env python3
"""
Unsloth QLoRA finetuning for Poseidon phishing detection.
Trains Gemma 3 1B on the combined DeepSeek-labeled dataset, exports GGUF.

Uses FastModel (new unified API) with get_chat_template and train_on_responses_only.

Env vars:
  POSEIDON_FINETUNE_DATASET    path to JSONL dataset
  POSEIDON_FINETUNE_OUTPUT_DIR output directory
  POSEIDON_FINETUNE_MODEL      base model name
  POSEIDON_FINETUNE_EPOCHS     number of epochs
  POSEIDON_FINETUNE_LR         learning rate
  POSEIDON_FINETUNE_BATCH_SIZE per-device batch size
  POSEIDON_FINETUNE_GRAD_ACCUM gradient accumulation steps
  POSEIDON_FINETUNE_MAX_LEN    max sequence length
  POSEIDON_FINETUNE_R          LoRA rank
  POSEIDON_FINETUNE_LOGGING_STEPS logging interval
  POSEIDON_FINETUNE_QUANT      quantization (4bit/8bit/None)
  POSEIDON_SKIP_GGUF           set to skip GGUF export
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

os.environ.setdefault("UNSLOTH_RETURN_LOGITS", "1")
os.environ["UNSLOTH_COMPILE_DISABLE"] = "1"
os.environ["UNSLOTH_FUSED_CE_COMPILE_DISABLE"] = "1"
os.environ["UNSLOTH_DISABLE_DOUBLE_BUFFER"] = "1"
os.environ["UNSLOTH_CE_LOSS_TARGET_GB"] = "0.25"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
import unsloth  # noqa: F401

import torch
from datasets import Dataset
from trl import SFTTrainer, SFTConfig
from unsloth import FastModel, is_bfloat16_supported
from unsloth.chat_templates import get_chat_template, standardize_data_formats, train_on_responses_only


@dataclass
class Config:
    dataset: str = "data/finetune/poseidon_training_combined.jsonl"
    output_dir: str = "models/finetuned"
    model: str = "unsloth/gemma-3-1b-it-unsloth-bnb-4bit"
    epochs: int = 1
    lr: float = 2e-4
    batch_size: int = 4
    grad_accum: int = 4
    max_len: int = 768
    lora_r: int = 16
    logging_steps: int = 10
    quant: str = "4bit"
    skip_gguf: bool = False
    hf_token: str = ""

    @classmethod
    def from_env(cls):
        env = os.environ
        return cls(
            dataset=env.get("POSEIDON_FINETUNE_DATASET", cls.dataset),
            output_dir=env.get("POSEIDON_FINETUNE_OUTPUT_DIR", cls.output_dir),
            model=env.get("POSEIDON_FINETUNE_MODEL", cls.model),
            epochs=int(env.get("POSEIDON_FINETUNE_EPOCHS", str(cls.epochs))),
            lr=float(env.get("POSEIDON_FINETUNE_LR", str(cls.lr))),
            batch_size=int(env.get("POSEIDON_FINETUNE_BATCH_SIZE", str(cls.batch_size))),
            grad_accum=int(env.get("POSEIDON_FINETUNE_GRAD_ACCUM", str(cls.grad_accum))),
            max_len=int(env.get("POSEIDON_FINETUNE_MAX_LEN", str(cls.max_len))),
            lora_r=int(env.get("POSEIDON_FINETUNE_R", str(cls.lora_r))),
            logging_steps=int(env.get("POSEIDON_FINETUNE_LOGGING_STEPS", str(cls.logging_steps))),
            quant=env.get("POSEIDON_FINETUNE_QUANT", cls.quant),
            skip_gguf=env.get("POSEIDON_SKIP_GGUF", "").lower() in ("1", "true", "yes"),
            hf_token=env.get("HF_TOKEN", ""),
        )


def load_dataset_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    print(f"Loaded {len(rows)} rows from {path}")
    return rows


def format_conversation(row: dict) -> dict | None:
    prompt = row.get("prompt", "")
    response = row.get("assistant_raw", "")
    if not prompt or not response:
        return None
    return {
        "conversations": [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": response},
        ]
    }


def main():
    config = Config.from_env()
    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Load and format dataset
    raw = load_dataset_jsonl(config.dataset)
    records = []
    for row in raw:
        conv = format_conversation(row)
        if conv is not None:
            records.append(conv)

    if not records:
        print("ERROR: no valid training rows")
        sys.exit(1)

    ds = Dataset.from_list(records)
    print(f"Conversations: {len(ds)}")

    # Load model with FastModel (new unified API)
    model, tokenizer = FastModel.from_pretrained(
        model_name=config.model,
        max_seq_length=config.max_len,
        load_in_4bit=(config.quant == "4bit"),
        load_in_8bit=(config.quant == "8bit"),
        token=config.hf_token or None,
        device_map="auto",
        use_gradient_checkpointing="unsloth",
    )

    # Apply LoRA
    model = FastModel.get_peft_model(
        model,
        finetune_vision_layers=False,
        finetune_language_layers=True,
        finetune_attention_modules=True,
        finetune_mlp_modules=True,
        r=config.lora_r,
        lora_alpha=config.lora_r,
        lora_dropout=0,
        bias="none",
        random_state=42,
        use_gradient_checkpointing="unsloth",
    )
    model.print_trainable_parameters()

    # Set gemma-3 chat template and standardize data format
    tokenizer = get_chat_template(tokenizer, chat_template="gemma-3")
    ds = standardize_data_formats(ds)

    # Format text field (remove <bos> since processor adds it)
    def fmt(example):
        text = tokenizer.apply_chat_template(
            example["conversations"], tokenize=False, add_generation_prompt=False
        ).removeprefix("<bos>")
        return {"text": text}

    ds = ds.map(fmt)

    # Training args
    training_args = SFTConfig(
        output_dir=str(out / "checkpoints"),
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.batch_size,
        gradient_accumulation_steps=config.grad_accum,
        warmup_steps=10,
        logging_steps=config.logging_steps,
        learning_rate=config.lr,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        save_strategy="epoch",
        report_to="none",
        dataloader_num_workers=0,
        max_seq_length=config.max_len,
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=ds,
        args=training_args,
    )

    # Only train on assistant responses
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<start_of_turn>user\n",
        response_part="<start_of_turn>model\n",
    )

    # Train
    total_steps = len(ds) / (config.batch_size * config.grad_accum) * config.epochs
    print(f"{len(ds)} rows, {config.epochs} epochs ~ {total_steps:.0f} steps", flush=True)
    trainer.train()

    # Save adapter
    adapter_path = out / "adapter"
    trainer.model.save_pretrained(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    print(f"Adapter saved to {adapter_path}")

    # Export GGUF
    if config.skip_gguf:
        print("Skipping GGUF export")
    else:
        model_dir = Path("models")
        model_dir.mkdir(parents=True, exist_ok=True)
        print("Exporting GGUF...")
        gguf_dest = model_dir / "Theseus-v2.gguf"
        exported = False

        # 1) Try new FastModel save_pretrained_gguf (no GCC needed, Q4_K_M)
        if not exported:
            try:
                gguf_tmp = out / "gguf_tmp"
                gguf_tmp.mkdir(parents=True, exist_ok=True)
                model.save_pretrained_gguf(
                    str(gguf_tmp), tokenizer,
                    quantization_method="q4_k_m",
                )
                gguf_files = list(gguf_tmp.glob("*.gguf"))
                if gguf_files:
                    import shutil
                    shutil.copy2(str(gguf_files[0]), str(gguf_dest))
                    print(f"GGUF exported (Q4_K_M): {gguf_dest}")
                    exported = True
            except Exception as e:
                print(f"save_pretrained_gguf failed: {e}")

        # 2) Fallback: old unsloth_save_pretrained_gguf (needs GCC)
        if not exported:
            try:
                from unsloth.save import unsloth_save_pretrained_gguf
                gguf_tmp = out / "gguf_tmp"
                gguf_tmp.mkdir(parents=True, exist_ok=True)
                unsloth_save_pretrained_gguf(
                    trainer.model,
                    save_directory=str(gguf_tmp),
                    tokenizer=tokenizer,
                    quantization_method="q4_k_m",
                )
                gguf_files = list(gguf_tmp.glob("*.gguf"))
                if gguf_files:
                    import shutil
                    shutil.copy2(str(gguf_files[0]), str(gguf_dest))
                    print(f"GGUF exported (Q4_K_M): {gguf_dest}")
                    exported = True
            except Exception as e:
                print(f"unsloth_save_pretrained_gguf failed: {e}")

        # 3) Last resort: save merged 16-bit, convert via external llama.cpp
        if not exported:
            try:
                merged = out / "merged"
                merged.mkdir(parents=True, exist_ok=True)
                model.save_pretrained_merged(str(merged), tokenizer)
                print(f"Merged 16-bit model saved to {merged}")
                print("To convert to GGUF: python external/llama.cpp/convert_hf_to_gguf.py merged/ --outfile models/Theseus-v2.gguf")
            except Exception as e:
                print(f"save_pretrained_merged failed: {e}")

    print("Training complete!")


if __name__ == "__main__":
    main()
