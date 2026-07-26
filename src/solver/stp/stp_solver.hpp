/***
 * Murxla: A Model-Based API Fuzzer for SMT solvers.
 *
 * This file is part of Murxla.
 *
 * Copyright (C) 2019-2022 by the authors listed in the AUTHORS file.
 *
 * See LICENSE for more information on using this software.
 */
#ifdef MURXLA_USE_STP

#ifndef __MURXLA__STP_SOLVER_H
#define __MURXLA__STP_SOLVER_H

#include "fsm.hpp"
#include "solver/solver.hpp"
#include "stp/c_interface.h"
#include "theory.hpp"

namespace murxla {
namespace stp {

/* -------------------------------------------------------------------------- */
/* StpSort                                                                    */
/* -------------------------------------------------------------------------- */

class StpSort : public AbsSort
{
  friend class StpSolver;

 public:
  /** Construct a Bool sort. */
  StpSort() : d_kind(SORT_BOOL) {}
  /** Construct a bit-vector sort of size bv_size. */
  StpSort(uint32_t bv_size) : d_kind(SORT_BV), d_bv_size(bv_size) {}
  /** Construct an array sort with given index and element bit-widths. */
  StpSort(uint32_t index_size, uint32_t element_size)
      : d_kind(SORT_ARRAY),
        d_index_size(index_size),
        d_element_size(element_size)
  {
  }
  /**
   * Construct a sort of the given kind. Used for the RoundingMode sort
   * (SORT_RM), which carries no parameters.
   */
  StpSort(SortKind kind) : d_kind(kind) {}
  /** Construct a floating-point sort with exponent/significand widths. */
  StpSort(SortKind kind, uint32_t exp_size, uint32_t sig_size)
      : d_kind(kind), d_exp_size(exp_size), d_sig_size(sig_size)
  {
  }
  ~StpSort() override{};

  size_t hash() const override;
  bool equals(const Sort& other) const override;
  std::string to_string() const override;
  bool is_array() const override;
  bool is_bool() const override;
  bool is_bv() const override;
  bool is_fp() const override;
  bool is_rm() const override;
  uint32_t get_bv_size() const override;
  uint32_t get_fp_exp_size() const override;
  uint32_t get_fp_sig_size() const override;
  Sort get_array_index_sort() const override;
  Sort get_array_element_sort() const override;

 private:
  /** The sort kind (SORT_BOOL, SORT_BV, SORT_ARRAY, SORT_FP or SORT_RM). */
  SortKind d_kind;
  /** The bit-vector size (SORT_BV only). */
  uint32_t d_bv_size = 0;
  /** The index bit-width (SORT_ARRAY only). */
  uint32_t d_index_size = 0;
  /** The element bit-width (SORT_ARRAY only). */
  uint32_t d_element_size = 0;
  /** The exponent bit-width (SORT_FP only). */
  uint32_t d_exp_size = 0;
  /** The significand bit-width, including the hidden bit (SORT_FP only). */
  uint32_t d_sig_size = 0;
};

/* -------------------------------------------------------------------------- */
/* StpTerm                                                                    */
/* -------------------------------------------------------------------------- */

class StpTerm : public AbsTerm
{
  friend class StpSolver;

 public:
  /** Get wrapped STP expression from Murxla term. */
  static Expr get_stp_term(Term term);

  StpTerm(Expr term) : d_term(term) {}
  ~StpTerm() override{};

  size_t hash() const override;
  bool equals(const Term& other) const override;
  std::string to_string() const override;
  bool is_bool_value() const override;
  bool is_bv_value() const override;
  bool is_fp_value() const override;
  bool is_rm_value() const override;
  bool is_special_value(const SpecialValueKind& kind) const override;
  bool is_const() const override;
  bool is_value() const override;
  bool is_var() const override;

 private:
  /** The wrapped STP expression. */
  Expr d_term = nullptr;
};

/* -------------------------------------------------------------------------- */
/* StpSolver                                                                  */
/* -------------------------------------------------------------------------- */

class StpSolver : public Solver
{
 public:
  /** Solver-specific operators (bit-vector overflow predicates). */
  inline static const Op::Kind OP_UADDO = "stp-OP_UADDO";
  inline static const Op::Kind OP_SADDO = "stp-OP_SADDO";
  inline static const Op::Kind OP_USUBO = "stp-OP_USUBO";
  inline static const Op::Kind OP_SSUBO = "stp-OP_SSUBO";
  inline static const Op::Kind OP_UMULO = "stp-OP_UMULO";
  inline static const Op::Kind OP_SMULO = "stp-OP_SMULO";

  StpSolver(SolverSeedGenerator& sng) : Solver(sng), d_solver(nullptr) {}
  ~StpSolver() override;

  void new_solver() override;
  void delete_solver() override;
  bool is_initialized() const override;
  const std::string get_name() const override;
  const std::string get_profile() const override;

  void configure_opmgr(OpKindManager* opmgr) const override;
  void disable_unsupported_actions(FSM* fsm) const override;

  bool is_unsat_assumption(const Term& t) const override;

  std::string get_option_name_incremental() const override;
  std::string get_option_name_model_gen() const override;
  std::string get_option_name_unsat_assumptions() const override;
  std::string get_option_name_unsat_cores() const override;

  bool option_incremental_enabled() const override;
  bool option_model_gen_enabled() const override;
  bool option_unsat_assumptions_enabled() const override;
  bool option_unsat_cores_enabled() const override;

  Term mk_var(Sort sort, const std::string& name) override;
  Term mk_const(Sort sort, const std::string& name) override;
  Term mk_fun(const std::string& name,
              const std::vector<Term>& args,
              Term body) override;

  Term mk_value(Sort sort, bool value) override;
  Term mk_value(Sort sort, const std::string& value) override;
  Term mk_value(Sort sort, const std::string& value, Base base) override;

  Term mk_special_value(Sort sort,
                        const AbsTerm::SpecialValueKind& value) override;

  Sort mk_sort(SortKind kind) override;
  Sort mk_sort(SortKind kind, uint32_t size) override;
  Sort mk_sort(SortKind kind, uint32_t esize, uint32_t ssize) override;
  Sort mk_sort(SortKind kind, const std::vector<Sort>& sorts) override;

  Term mk_term(const Op::Kind& kind,
               const std::vector<Term>& args,
               const std::vector<uint32_t>& indices,
               const std::vector<std::string>& special_args = {}) override;

  Sort get_sort(Term term, SortKind sort_kind) override;

  void assert_formula(const Term& t) override;

  Result check_sat() override;
  Result check_sat_assuming(const std::vector<Term>& assumptions) override;

  std::vector<Term> get_unsat_assumptions() override;

  std::vector<Term> get_value(const std::vector<Term>& terms) override;

  void push(uint32_t n_levels) override;
  void pop(uint32_t n_levels) override;

  void print_model() override;

  void reset() override;
  void reset_assertions() override;

  void set_opt(const std::string& opt, const std::string& value) override;

 private:
  /** Reconstruct the STP type handle for the given murxla sort. */
  Type get_stp_type(Sort sort) const;
  /** Convert a vector of murxla terms to STP expressions. */
  std::vector<Expr> terms_to_stp_terms(const std::vector<Term>& terms) const;
  /**
   * Pop the internal scope pushed by check_sat_assuming (assumptions are
   * emulated via push/assert/query/pop; the pop is deferred so that model
   * queries remain valid after a satisfiable check-sat-assuming call).
   */
  void pop_pending_assumption_scope();

#ifdef MURXLA_STP_HAVE_FP
  /** True if kind is a floating-point operator handled by mk_term_fp. */
  static bool is_fp_kind(const Op::Kind& kind);
  /** Build a floating-point (or FP conversion) term. */
  Expr mk_term_fp(const Op::Kind& kind,
                  std::vector<Expr>& args,
                  const std::vector<uint32_t>& indices) const;
#endif

  Expr mk_term_left_assoc(std::vector<Expr>& args,
                          const std::function<Expr(Expr, Expr)>& fun) const;
  Expr mk_term_right_assoc(std::vector<Expr>& args,
                           const std::function<Expr(Expr, Expr)>& fun) const;
  Expr mk_term_pairwise(std::vector<Expr>& args,
                        const std::function<Expr(Expr, Expr)>& fun) const;
  Expr mk_term_chained(std::vector<Expr>& args,
                       const std::function<Expr(Expr, Expr)>& fun) const;

  /** The STP validity checker instance. */
  VC d_solver;
  /** True if murxla enabled incremental mode for this run. */
  bool d_incremental = false;
  /** True if murxla enabled model generation for this run. */
  bool d_model_gen = false;
  /** True if check_sat_assuming pushed a scope that still needs popping. */
  bool d_pending_assumption_pop = false;
  /** Counter for generating unique symbol names. */
  uint64_t d_num_symbols = 0;
};

}  // namespace stp
}  // namespace murxla

#endif

#endif
