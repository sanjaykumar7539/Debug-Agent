Rotating JSON logs are created here at runtime: agent.jsonl plus up to 3 backups.
Each file is capped at roughly 1 MB. Events include stage, job ID, count and status.
No source, prompt, error log, API response, or hidden model reasoning is logged.
Set DEBUG_AGENT_LOG_DIR to choose a different directory.
