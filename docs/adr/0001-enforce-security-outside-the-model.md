# ADR 0001: Enforce security outside the model

- Status: accepted
- Date: 2026-11-23

## Context

Personal agents combine private data, untrusted content, and the ability to act. Prompt
injection lets anyone who can put text in front of the model influence it, and no current model
resists this reliably. Many agent frameworks rely on system-prompt instructions ("never send
email without asking") for safety; those instructions are themselves just text the attacker can
argue with.

## Decision

The model is treated as an untrusted planner. Every tool call it proposes passes through
deterministic code before execution:

1. Arguments are validated against the tool's strict schema.
2. The policy engine decides `allow`, `ask`, or `deny` from the tool's declared risk tier, the
   owner's policy file, and the turn's taint state. The model has no input into this decision
   other than the proposed call itself.
3. `ask` decisions produce an approval bound to a hash of the exact arguments.
4. Every step is written to the hash-chained audit log.

System-prompt guidance still exists to make the model *behave well*, but no security property
depends on it.

## Consequences

- Security properties can be unit-tested without a model, using a fake provider that emits
  hostile tool calls on purpose.
- Some legitimate workflows need an approval tap. The policy file lets the owner relax rules
  explicitly, and every relaxation is visible in one place.
- Provider choice does not affect security guarantees, so supporting any LLM provider is safe.
