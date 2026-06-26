# Limitations

The current implementation is an assurance substrate, not a complete evaluator.
It runs deterministic local fixtures, but it does not evaluate live models,
compare stochastic providers, certify safety, or validate clinical workflows.
In-process fixture runs capture ordinary Python exceptions; catastrophic process
termination remains outside the current runtime boundary.
