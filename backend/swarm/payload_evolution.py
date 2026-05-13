"""
Quantara Payload Evolution Engine
====================================
Genetic algorithm for adaptive payload mutation and evolution.

Inspired by genetic programming:
    1. Generate initial population from PayloadsAllTheThings
    2. Execute payload tests against target
    3. Evaluate fitness based on server response behavior
    4. Select best-performing payloads (tournament selection)
    5. Crossover + mutate selected payloads
    6. Repeat for multiple generations

Fitness is computed from:
    - Status code deviation from baseline
    - Response body size delta
    - Response time anomaly
    - Error/reflection/indicator detection
    - WAF bypass success
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Fitness Evaluation
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FitnessResult:
    """Fitness evaluation of a single payload execution."""
    payload:         str
    fitness:         float = 0.0
    status_code:     int = 0
    response_size:   int = 0
    response_time:   float = 0.0
    triggered_error: bool = False
    reflected:       bool = False
    waf_bypassed:    bool = False
    evidence:        str = ""
    generation:      int = 0

    @property
    def is_successful(self) -> bool:
        return self.fitness >= 0.7


@dataclass
class EvolutionConfig:
    """Configuration for the evolution engine."""
    population_size:    int = 40
    max_generations:    int = 5
    mutation_rate:      float = 0.3
    crossover_rate:     float = 0.4
    elite_ratio:        float = 0.2    # top N% survive unchanged
    tournament_size:    int = 3
    fitness_threshold:  float = 0.8    # early stop if best fitness exceeds this
    max_runtime_sec:    float = 30.0   # hard time limit


# ═══════════════════════════════════════════════════════════════════════════════
# Mutation Operators
# ═══════════════════════════════════════════════════════════════════════════════

class MutationOperators:
    """Library of payload mutation operators."""

    @staticmethod
    def url_encode(payload: str) -> str:
        """Single URL encoding of special characters."""
        return "".join(
            f"%{ord(c):02x}" if c in "'\"><;&|`$(){}[]#!" else c
            for c in payload
        )

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding to bypass single-decode WAFs."""
        return payload.replace("<", "%253c").replace(">", "%253e") \
                      .replace("'", "%2527").replace('"', "%2522") \
                      .replace(" ", "%2520")

    @staticmethod
    def unicode_escape(payload: str) -> str:
        """Unicode escape encoding."""
        return "".join(
            f"\\u{ord(c):04x}" if c in "<>'\"&;|" else c
            for c in payload
        )

    @staticmethod
    def case_randomize(payload: str) -> str:
        """Randomize case of alphabetic characters."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def comment_inject_sql(payload: str) -> str:
        """Insert SQL comments between keywords."""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                     "INSERT", "UPDATE", "DELETE", "DROP", "TABLE"]
        result = payload
        for kw in keywords:
            # Case-insensitive replacement
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            if pattern.search(result):
                result = pattern.sub(lambda m: "/**/".join(m.group()), result, count=1)
        return result.replace(" ", "/**/")

    @staticmethod
    def null_byte_append(payload: str) -> str:
        """Append null byte to truncate WAF parsing."""
        return payload + "%00"

    @staticmethod
    def whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = ["\t", "\n", "\r", "%09", "%0a", "%0d", "+",
                        "/**/", "%20"]
        return payload.replace(" ", random.choice(alternatives))

    @staticmethod
    def string_concat_sql(payload: str) -> str:
        """Break strings using SQL concatenation."""
        if "'" in payload:
            return payload.replace("'", "'||'", 1)
        return payload

    @staticmethod
    def hex_encode_partial(payload: str) -> str:
        """Hex-encode random portions of the payload."""
        chars = list(payload)
        for i in range(len(chars)):
            if random.random() < 0.2 and chars[i].isalpha():
                chars[i] = f"&#x{ord(chars[i]):02x};"
        return "".join(chars)

    @staticmethod
    def polyglot_wrap(payload: str) -> str:
        """Wrap payload in polyglot context for multi-context injection."""
        wrappers = [
            f"';{payload}//",
            f'";{payload}//',
            f"`)]{payload}//",
            f"-->]]>{payload}<!--",
            f"}}{payload}{{",
        ]
        return random.choice(wrappers)

    @staticmethod
    def chunk_transfer(payload: str) -> str:
        """Fragment payload to evade pattern matching."""
        if len(payload) < 6:
            return payload
        mid = len(payload) // 2
        return payload[:mid] + "/**/" + payload[mid:]

    @staticmethod
    def protocol_mutation(payload: str) -> str:
        """Mutate protocol-level aspects of SSRF payloads."""
        mutations = {
            "http://":  ["hTtP://", "HTTP://", "ht\ttp://"],
            "https://": ["hTtPs://", "HTTPS://", "ht\ttps://"],
            "127.0.0.1": ["0x7f000001", "2130706433", "017700000001",
                           "127.1", "127.0.1"],
            "localhost": ["localHOST", "LOCALHOST", "127.0.0.1",
                          "[::1]", "0.0.0.0"],
        }
        result = payload
        for pattern, options in mutations.items():
            if pattern in result:
                result = result.replace(pattern, random.choice(options), 1)
                break
        return result

    ALL_OPERATORS = [
        url_encode, double_url_encode, unicode_escape, case_randomize,
        comment_inject_sql, null_byte_append, whitespace_variation,
        string_concat_sql, hex_encode_partial, polyglot_wrap,
        chunk_transfer, protocol_mutation,
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Crossover Operators
# ═══════════════════════════════════════════════════════════════════════════════

class CrossoverOperators:
    """Genetic crossover operators for combining payloads."""

    @staticmethod
    def single_point(parent_a: str, parent_b: str) -> Tuple[str, str]:
        """Single-point crossover at a random position."""
        if not parent_a or not parent_b:
            return parent_a, parent_b
        point_a = random.randint(1, max(1, len(parent_a) - 1))
        point_b = random.randint(1, max(1, len(parent_b) - 1))
        child_a = parent_a[:point_a] + parent_b[point_b:]
        child_b = parent_b[:point_b] + parent_a[point_a:]
        return child_a[:300], child_b[:300]

    @staticmethod
    def token_swap(parent_a: str, parent_b: str) -> Tuple[str, str]:
        """Swap tokens (delimited by special chars) between parents."""
        delims = re.compile(r"['\"\s<>/;|&=]+")
        tokens_a = delims.split(parent_a)
        tokens_b = delims.split(parent_b)
        if len(tokens_a) > 1 and len(tokens_b) > 1:
            idx = random.randint(0, min(len(tokens_a), len(tokens_b)) - 1)
            tokens_a[idx], tokens_b[idx] = tokens_b[idx], tokens_a[idx]
        return " ".join(tokens_a)[:300], " ".join(tokens_b)[:300]

    @staticmethod
    def prefix_suffix(parent_a: str, parent_b: str) -> Tuple[str, str]:
        """Combine prefix of one with suffix of another."""
        mid_a = len(parent_a) // 2
        mid_b = len(parent_b) // 2
        return (parent_a[:mid_a] + parent_b[mid_b:])[:300], \
               (parent_b[:mid_b] + parent_a[mid_a:])[:300]


# ═══════════════════════════════════════════════════════════════════════════════
# Payload Evolution Engine
# ═══════════════════════════════════════════════════════════════════════════════

# Type for the async fitness evaluator callback
FitnessEvaluator = Callable[[str, str, str], Any]  # (payload, endpoint, vector_type) -> FitnessResult


class PayloadEvolutionEngine:
    """
    Genetic algorithm engine for payload evolution.

    Usage:
        engine = PayloadEvolutionEngine(config)
        evolved = await engine.evolve(
            seed_payloads=["' OR 1=1--", "<script>alert(1)</script>"],
            vector_type="sqli",
            endpoint="https://target.com/api/search",
            evaluator=my_fitness_function,
        )
    """

    def __init__(self, config: EvolutionConfig = None):
        self.config = config or EvolutionConfig()
        self._generation_history: List[Dict[str, Any]] = []

    async def evolve(
        self,
        seed_payloads: List[str],
        vector_type: str,
        endpoint: str,
        evaluator: FitnessEvaluator,
    ) -> List[FitnessResult]:
        """
        Run the genetic evolution loop.

        Args:
            seed_payloads: Initial population of payloads
            vector_type: Attack vector type (sqli, xss, cmdi, etc.)
            endpoint: Target endpoint to test against
            evaluator: Async function that tests a payload and returns FitnessResult

        Returns:
            List of FitnessResult sorted by fitness (best first)
        """
        start_time = time.monotonic()

        # Build initial population
        population = self._init_population(seed_payloads, vector_type)
        all_results: List[FitnessResult] = []
        best_fitness = 0.0

        for gen in range(self.config.max_generations):
            # Time check
            if time.monotonic() - start_time > self.config.max_runtime_sec:
                logger.info(f"[Evolution] Time limit reached at gen {gen}")
                break

            # Evaluate fitness for current generation
            gen_results = await self._evaluate_generation(
                population, endpoint, vector_type, evaluator, gen
            )
            all_results.extend(gen_results)

            # Track best
            gen_best = max(gen_results, key=lambda r: r.fitness) if gen_results else None
            if gen_best:
                best_fitness = max(best_fitness, gen_best.fitness)

            # Record generation stats
            avg_fitness = (
                sum(r.fitness for r in gen_results) / len(gen_results)
                if gen_results else 0.0
            )
            self._generation_history.append({
                "generation": gen,
                "population_size": len(population),
                "best_fitness": round(best_fitness, 3),
                "avg_fitness": round(avg_fitness, 3),
                "successful": sum(1 for r in gen_results if r.is_successful),
            })

            logger.info(
                f"[Evolution] Gen {gen}: best={best_fitness:.3f} avg={avg_fitness:.3f} "
                f"pop={len(population)} successes={sum(1 for r in gen_results if r.is_successful)}"
            )

            # Early stopping
            if best_fitness >= self.config.fitness_threshold:
                logger.info(f"[Evolution] Fitness threshold reached at gen {gen}")
                break

            # Selection + crossover + mutation for next generation
            population = self._next_generation(gen_results, vector_type)

        # Sort all results by fitness
        all_results.sort(key=lambda r: r.fitness, reverse=True)
        return all_results

    def _init_population(self, seeds: List[str], vector_type: str) -> List[str]:
        """Build initial population from seeds + mutations."""
        population = list(seeds)

        # Add mutations of each seed
        mutation_ops = self._get_operators_for_vector(vector_type)
        while len(population) < self.config.population_size:
            seed = random.choice(seeds) if seeds else ""
            if not seed:
                break
            op = random.choice(mutation_ops)
            try:
                mutant = op(seed) if not isinstance(op, staticmethod) else op.__func__(seed)
            except Exception:
                mutant = seed
            if mutant and mutant not in population:
                population.append(mutant[:300])

        return population[:self.config.population_size]

    async def _evaluate_generation(
        self,
        population: List[str],
        endpoint: str,
        vector_type: str,
        evaluator: FitnessEvaluator,
        generation: int,
    ) -> List[FitnessResult]:
        """Evaluate fitness of all payloads in the current generation."""
        results: List[FitnessResult] = []

        # Evaluate in small batches to respect rate limiting
        batch_size = 5
        for i in range(0, len(population), batch_size):
            batch = population[i:i + batch_size]
            tasks = []
            for payload in batch:
                tasks.append(self._evaluate_single(
                    payload, endpoint, vector_type, evaluator, generation
                ))
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in batch_results:
                if isinstance(res, FitnessResult):
                    results.append(res)
            await asyncio.sleep(0.05)  # rate limit between batches

        return results

    async def _evaluate_single(
        self,
        payload: str,
        endpoint: str,
        vector_type: str,
        evaluator: FitnessEvaluator,
        generation: int,
    ) -> FitnessResult:
        """Evaluate a single payload's fitness."""
        try:
            result = await evaluator(payload, endpoint, vector_type)
            if isinstance(result, FitnessResult):
                result.generation = generation
                return result
            # If evaluator returns a dict, convert
            if isinstance(result, dict):
                return FitnessResult(
                    payload=payload,
                    fitness=result.get("fitness", 0.0),
                    status_code=result.get("status_code", 0),
                    response_size=result.get("response_size", 0),
                    response_time=result.get("response_time", 0.0),
                    triggered_error=result.get("triggered_error", False),
                    reflected=result.get("reflected", False),
                    waf_bypassed=result.get("waf_bypassed", False),
                    evidence=result.get("evidence", ""),
                    generation=generation,
                )
        except Exception as exc:
            logger.debug(f"[Evolution] Eval error: {exc}")

        return FitnessResult(payload=payload, fitness=0.0, generation=generation)

    def _next_generation(self, results: List[FitnessResult],
                          vector_type: str) -> List[str]:
        """Create next generation via selection, crossover, and mutation."""
        if not results:
            return []

        sorted_results = sorted(results, key=lambda r: r.fitness, reverse=True)
        pop_size = self.config.population_size

        # Elite selection — top performers survive unchanged
        elite_count = max(1, int(pop_size * self.config.elite_ratio))
        next_gen = [r.payload for r in sorted_results[:elite_count]]

        # Tournament selection + crossover + mutation
        mutation_ops = self._get_operators_for_vector(vector_type)
        crossover_ops = [
            CrossoverOperators.single_point,
            CrossoverOperators.token_swap,
            CrossoverOperators.prefix_suffix,
        ]

        while len(next_gen) < pop_size:
            # Tournament selection
            parent_a = self._tournament_select(sorted_results)
            parent_b = self._tournament_select(sorted_results)

            if random.random() < self.config.crossover_rate and parent_a != parent_b:
                # Crossover
                op = random.choice(crossover_ops)
                child_a, child_b = op(parent_a.payload, parent_b.payload)
                candidates = [child_a, child_b]
            else:
                candidates = [parent_a.payload]

            for child in candidates:
                if len(next_gen) >= pop_size:
                    break
                # Mutation
                if random.random() < self.config.mutation_rate:
                    op = random.choice(mutation_ops)
                    try:
                        child = op(child) if callable(op) else child
                    except Exception:
                        pass
                if child and child not in next_gen:
                    next_gen.append(child[:300])

        return next_gen[:pop_size]

    def _tournament_select(self, results: List[FitnessResult]) -> FitnessResult:
        """Select a parent via tournament selection."""
        tournament = random.sample(
            results, min(self.config.tournament_size, len(results))
        )
        return max(tournament, key=lambda r: r.fitness)

    def _get_operators_for_vector(self, vector_type: str) -> List[Callable]:
        """Get mutation operators appropriate for the vector type."""
        base = [
            MutationOperators.url_encode,
            MutationOperators.double_url_encode,
            MutationOperators.case_randomize,
            MutationOperators.null_byte_append,
            MutationOperators.whitespace_variation,
            MutationOperators.hex_encode_partial,
            MutationOperators.chunk_transfer,
        ]
        if vector_type in ("sqli", "sql_injection"):
            base.extend([
                MutationOperators.comment_inject_sql,
                MutationOperators.string_concat_sql,
            ])
        if vector_type in ("xss", "cross_site_scripting"):
            base.extend([
                MutationOperators.unicode_escape,
                MutationOperators.polyglot_wrap,
            ])
        if vector_type in ("ssrf",):
            base.extend([
                MutationOperators.protocol_mutation,
            ])
        return base

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._generation_history)

    def reset(self) -> None:
        self._generation_history.clear()
