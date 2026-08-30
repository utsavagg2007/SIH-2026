"""Layer 8 - the AI security analyst.

Deliberately a separate process from the backend. The backend proves it makes
no outbound connection except to its own alert database, and
``GET /api/v1/system/constraints`` walks its live route table to say so. Putting
a hosted-model call inside that process would falsify the proof. Here the egress
is real, named, and confined to one module (:mod:`analyst.llm.gemini`).

The layer is optional by construction. Every requirement in the problem
statement is met with it switched off; see ``analyst/README.md``.
"""

__version__ = "0.1.0"
