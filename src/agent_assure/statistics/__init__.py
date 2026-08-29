"""Dependency-light statistical engines used by assurance evaluators."""

from agent_assure.statistics.cluster_binomial import (
    BINARY_CLUSTER_ASSUMPTION,
    MAX_CLUSTERS,
    MAX_MONTE_CARLO_BERNOULLI_DRAWS,
    MAX_MONTE_CARLO_RESAMPLES,
    MONTE_CARLO_SEED_DOMAIN,
    PROBABILITY_SCALE,
    RATIONAL_BERNOULLI_SAMPLER_ID,
    SHA256_COUNTER_BITSTREAM_ID,
    ClusterBinomialAnalysis,
    ClusterBinomialDesign,
    MonteCarloBinomialDiagnostic,
    analyze_cluster_binomial,
    clear_cluster_binomial_caches,
    cluster_binomial_rejection_region_contains,
    exact_binomial_upper_tail,
    plan_cluster_binomial_design,
)

__all__ = [
    "BINARY_CLUSTER_ASSUMPTION",
    "MAX_CLUSTERS",
    "MAX_MONTE_CARLO_BERNOULLI_DRAWS",
    "MAX_MONTE_CARLO_RESAMPLES",
    "MONTE_CARLO_SEED_DOMAIN",
    "PROBABILITY_SCALE",
    "RATIONAL_BERNOULLI_SAMPLER_ID",
    "SHA256_COUNTER_BITSTREAM_ID",
    "ClusterBinomialAnalysis",
    "ClusterBinomialDesign",
    "MonteCarloBinomialDiagnostic",
    "analyze_cluster_binomial",
    "clear_cluster_binomial_caches",
    "cluster_binomial_rejection_region_contains",
    "exact_binomial_upper_tail",
    "plan_cluster_binomial_design",
]
