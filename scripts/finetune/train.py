#!/usr/bin/env python3
"""
Unsloth QLoRA finetuning for Poseidon phishing detection.
Trains Gemma 3 1B on the DeepSeek-labeled dataset, exports GGUF.

Env vars:
  POSEIDON_FINETUNE_DATASET   path to JSONL dataset
  POSEIDON_FINETUNE_OUTPUT_DIR  output directory
  POSEIDON_FINETUNE_MODEL     base model name
  POSEIDON_FINETUNE_EPOCHS    number of epochs
  POSEIDON_FINETUNE_LR        learning rate
  POSEIDON_FINETUNE_BATCH_SIZE  per-device batch size
  POSEIDON_FINETUNE_GRAD_ACCUM  gradient accumulation steps
  POSEIDON_FINETUNE_MAX_LEN   max sequence length
  POSEIDON_FINETUNE_R         LoRA rank
  POSEIDON_FINETUNE_ALPHA     LoRA alpha
  POSEIDON_FINETUNE_DROPOUT   LoRA dropout
  POSEIDON_FINETUNE_QUANT     quantization (4bit/8bit/None)
  POSEIDON_SKIP_GGUF          set to skip GGUF export
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

# Unsloth must be imported before transformers/trl/peft, and TRL needs logits.
os.environ.setdefault("UNSLOTH_RETURN_LOGITS", "1")
import unsloth  # noqa: F401

import torch
from datasets import Dataset
from transformers import DataCollatorForSeq2Seq
from trl import SFTTrainer, SFTConfig
from unsloth import FastLanguageModel, is_bfloat16_supported


@dataclass
class Config:
    dataset: str = "data/finetune/deepseek_phishing_training.jsonl"
    output_dir: str = "models/finetuned"
    model: str = "unsloth/gemma-3-1b-it-bnb-4bit"
    epochs: int = 3
    lr: float = 2e-4
    batch_size: int = 2
    grad_accum: int = 4
    max_len: int = 2048
    lora_r: int = 16
    lora_alpha: int = 16
    lora_dropout: float = 0.0
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
            lora_alpha=int(env.get("POSEIDON_FINETUNE_ALPHA", str(cls.lora_alpha))),
            lora_dropout=float(env.get("POSEIDON_FINETUNE_DROPOUT", str(cls.lora_dropout))),
            quant=env.get("POSEIDON_FINETUNE_QUANT", cls.quant),
            skip_gguf=env.get("POSEIDON_SKIP_GGUF", "").lower() in ("1", "true", "yes"),
            hf_token=env.get("HF_TOKEN", ""),
        )


def load_dataset_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            rows.append(row)
    print(f"Loaded {len(rows)} rows from {path}")
    return rows


def format_conversation(row: dict) -> list[dict]:
    prompt = row.get("prompt", "")
    response = row.get("assistant_raw", "")
    if not prompt or not response:
        return None
    return [
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": response},
    ]


def main():
    config = Config.from_env()

    # Create output dir
    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Load and format dataset
    raw = load_dataset_jsonl(config.dataset)
    conversations = []
    skipped = 0
    for row in raw:
        conv = format_conversation(row)
        if conv is None:
            skipped += 1
            continue
        conversations.append({"messages": conv})

    if skipped:
        print(f"Skipped {skipped} rows with missing prompt/response")

    if not conversations:
        print("ERROR: no valid training rows")
        sys.exit(1)

    print(f"Conversations: {len(conversations)}")

    # Load model
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config.model,
        max_seq_length=config.max_len,
        dtype=None,
        load_in_4bit=(config.quant == "4bit"),
        load_in_8bit=(config.quant == "8bit"),
        token=config.hf_token or None,
        device_map="auto",
    )

    # Apply LoRA
    model = FastLanguageModel.get_peft_model(
        model,
        r=config.lora_r,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
        use_rslora=False,
        loftq_config=None,
    )

    # Pre-format and pre-tokenize all conversations
    def format_messages(messages):
        return tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False,
        )

    formatted_texts = [format_messages(ex["messages"]) for ex in conversations]
    print(f"Formatted {len(formatted_texts)} examples")
    if formatted_texts:
        print(f"Example (first 200 chars): {formatted_texts[0][:200]}")

    # Tokenize with labels for completion-only loss
    # Labels: -100 for user tokens, token IDs for assistant tokens
    response_token_ids = tokenizer.encode("<start_of_turn>model\n", add_special_tokens=False)

    input_ids_list = []
    labels_list = []
    skipped_long = 0
    for text in formatted_texts:
        tokens = tokenizer.encode(text, truncation=True, max_length=config.max_len)
        labels = [-100] * len(tokens)
        # Find all assistant turns and set their labels
        i = 0
        while i < len(tokens):
            if tokens[i:i+len(response_token_ids)] == response_token_ids:
                # Mark from this position onward as trainable until next user turn or end
                for j in range(i, len(tokens)):
                    labels[j] = tokens[j]
                # Single-turn dataset: train on the assistant JSON response.
                break
            i += 1

        input_ids_list.append(tokens)
        labels_list.append(labels)

    print(f"Tokenized {len(input_ids_list)} examples ({skipped_long} skipped for length)")

    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding="longest",
        max_length=config.max_len,
        pad_to_multiple_of=8,
    )

    tokenized_dataset = Dataset.from_dict({
        "input_ids": input_ids_list,
        "labels": labels_list,
        "attention_mask": [[1]*len(ids) for ids in input_ids_list],
    })

    # Training config
    training_args = SFTConfig(
        output_dir=str(out / "checkpoints"),
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.batch_size,
        gradient_accumulation_steps=config.grad_accum,
        warmup_steps=5,
        logging_steps=1,
        learning_rate=config.lr,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        save_strategy="epoch",
        report_to="none",
        remove_unused_columns=True,
        dataloader_num_workers=0,
        max_length=config.max_len,
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=tokenized_dataset,
        data_collator=data_collator,
        args=training_args,
    )

    # Train
    print(f"Starting training for {config.epochs} epochs...")
    trainer.train()

    # Save adapter
    adapter_path = out / "adapter"
    trainer.model.save_pretrained(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    print(f"Adapter saved to {adapter_path}")

    # Export to GGUF directly from the trained model
    if config.skip_gguf:
        print("Skipping GGUF export (POSEIDON_SKIP_GGUF is set)")
    else:
        gguf_path = out / "poseidon-phishing-detect.gguf"
        print(f"Exporting to GGUF: {gguf_path}")
        # Export adapter to GGUF via Unsloth
        try:
            from unsloth.save import unsloth_save_pretrained_gguf
            unsloth_save_pretrained_gguf(
                trainer.model,
                save_directory=str(gguf_path),
                tokenizer=tokenizer,
                quantization_method="q4_k_m",
            )
            print(f"GGUF exported: {gguf_path}")
        except Exception as e:
            print(f"GGUF export failed (non-fatal): {e}")
            print("The LoRA adapter is still available for inference.")

    print("Training complete!")


if __name__ == "__main__":
    main()
