/***
 * Murxla: A Model-Based API Fuzzer for SMT solvers.
 *
 * This file is part of Murxla.
 *
 * Copyright (C) 2019-2022 by the authors listed in the AUTHORS file.
 *
 * See LICENSE for more information on using this software.
 */
#ifndef __MURXLA__OPTIONS_H
#define __MURXLA__OPTIONS_H

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>

#include "config.hpp"
#include "theory.hpp"

namespace murxla {

using SolverKind              = std::string;
const SolverKind SOLVER_BTOR  = "btor";
const SolverKind SOLVER_BITWUZLA = "bitwuzla";
const SolverKind SOLVER_CVC5  = "cvc5";
const SolverKind SOLVER_SMT2  = "smt2";
const SolverKind SOLVER_STP   = "stp";
const SolverKind SOLVER_YICES = "yices";

struct Options
{
  /** The seed for the random number generator. */
  uint64_t seed = 0;
  /** The verbosity level. */
  uint32_t verbosity = 0;
  /** The time limit for one test run (one API sequence). */
  double time = 1;
  /** The maximum number of test runs to perform. */
  uint32_t max_runs = 0;
  /** The number of parallel fuzzing jobs (1 = no parallelism). */
  uint32_t num_jobs = 1;

  /** True if seed is provided by user. */
  bool is_seeded = false;
  /** True to use simple instead of completely random symbols for inputs. */
  bool simple_symbols = true;
  /** True to only generate SMT-LIB compliant API traces. */
  bool smtlib_compliant = false;
  /** True to print statistics. */
  bool print_stats = false;
  /** True to print FSM configuration. */
  bool print_fsm = false;
  /** Restrict arithmetic operators to linear fragment. */
  bool arith_linear = false;
  /** True to enable option fuzzing. */
  bool fuzz_options = true;
  std::string fuzz_options_filter;

  /** The directory for tmp files (default: current). */
  std::string tmp_dir = "/tmp";
  /** The directory for output files (default: current). */
  std::string out_dir = "";

  /** The selected solver to test. */
  SolverKind solver;
  /** The path to the solver binary to test when --smt2 is enabled. */
  std::string solver_binary;
  /** The file to trace the API call sequence to. */
  std::string api_trace_file_name;
  /** The API trace file to replay. */
  std::string untrace_file_name;
  /** The file to dump the SMT-LIB2 representation of the current trace to. */
  std::string smt2_file_name;

  /**
   * True if the API trace of the current run should be reduced by means of
   * delta-debugging.
   * If seeded or when untracing, current trace will be reduced no matter if
   * it triggers an error or not. In continuous mode, only error inducing
   * traces are reduced.
   */
  bool dd = false;
  /** Ignore output on stdout when delta debugging. */
  bool dd_ignore_out = false;
  /** Ignore output on stderr when delta debugging. */
  bool dd_ignore_err = false;
  /**
   * Check for occurrence of this string in stdout output (rather than
   * matching against the whole stderr output) when delta debugging.
   */
  std::string dd_match_out;
  /**
   * Check for occurrence of this string in stderr output (rather than
   * matching against the whole stderr output) when delta debugging.
   */
  std::string dd_match_err;
  /** The file to write the reduced API trace to. */
  std::string dd_trace_file_name;

  /** The name of the solver to cross-check given solver with. */
  std::string cross_check;

  /** The name of the solver to use for checking. */
  std::string check_solver_name;
  /** Whether unsat core/unsat assumptions/model checking is enabled. */
  bool check_solver = false;

  /** Command line options that need to be set for enabled solver. */
  std::vector<std::pair<std::string, std::string>> solver_options;

  /** The list of currently enabled theories. */
  TheoryVector enabled_theories;
  /** The list of currently disabled theories. */
  TheorySet disabled_theories;

  /** Command line options to be traced. */
  std::string cmd_line_trace;

  /** Solver profile filename. */
  std::string solver_profile_filename;

  /** Output file for exporting errors in JSON format. */
  std::string export_errors_filename = "";

  /** Print native solver API trace. */
  bool solver_trace = false;

  /**
   * Only run check-sat on formulas that use FP/RM anywhere or array
   * equality/distinct (extensionality); skip pure-BV-without-extensionality.
   */
  bool require_fp_or_ext = false;

  /**
   * Only run check-sat on formulas that contain at least one uninterpreted
   * function application; skip everything else.
   */
  bool require_uf = false;
  /**
   * True to steer generation towards uninterpreted functions without gating
   * check-sat on one, which --require-uf also does. See --prefer-uf.
   */
  bool prefer_uf = false;

  /**
   * Force incremental mode on for every run, regardless of what the solver
   * reports or what option fuzzing would pick, so push/pop, check-sat-assuming
   * and between-solve model reads are always exercised. Assumes the solver can
   * solve incrementally.
   */
  bool force_incremental = false;
  /**
   * True to give every registered solver option a random value at the start
   * of every run, rather than leaving it to the handful of set-option actions
   * the FSM happens to take. See --fuzz-opts-all.
   */
  bool fuzz_options_all = false;
  /**
   * The widest bit-vector sort generation may build, capped at
   * MURXLA_BW_MAX. See --bw-max.
   */
  uint32_t bw_max = MURXLA_BW_MAX;
};
}  // namespace murxla
#endif
