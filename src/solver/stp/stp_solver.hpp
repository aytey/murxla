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
  /**
   * Construct an array sort with the given index and element sorts. Each may
   * be a bit-vector, floating-point or RoundingMode sort (matching what STP's
   * generalized vc_arrayType accepts).
   */
  StpSort(Sort index, Sort element)
      : d_kind(SORT_ARRAY), d_index_sort(index), d_element_sort(element)
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
  /**
   * Construct a function sort with the given domain and codomain sorts. STP
   * has no function type handle -- an uninterpreted function is declared by
   * signature, not built from a sort -- so this is pure Murxla-side
   * bookkeeping, consumed by StpSolver::mk_const.
   */
  StpSort(const std::vector<Sort>& domain, Sort codomain)
      : d_kind(SORT_FUN), d_fun_domain(domain), d_fun_codomain(codomain)
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
  bool is_fun() const override;
  bool is_rm() const override;
  uint32_t get_bv_size() const override;
  uint32_t get_fp_exp_size() const override;
  uint32_t get_fp_sig_size() const override;
  Sort get_array_index_sort() const override;
  Sort get_array_element_sort() const override;
  uint32_t get_fun_arity() const override;
  Sort get_fun_codomain_sort() const override;
  std::vector<Sort> get_fun_domain_sorts() const override;

 private:
  /** The sort kind (SORT_BOOL, SORT_BV, SORT_ARRAY, SORT_FP or SORT_RM). */
  SortKind d_kind;
  /** The bit-vector size (SORT_BV only). */
  uint32_t d_bv_size = 0;
  /** The index sort (SORT_ARRAY only); a BV, FP or RM sort. */
  Sort d_index_sort;
  /** The element sort (SORT_ARRAY only); a BV, FP or RM sort. */
  Sort d_element_sort;
  /** The exponent bit-width (SORT_FP only). */
  uint32_t d_exp_size = 0;
  /** The significand bit-width, including the hidden bit (SORT_FP only). */
  uint32_t d_sig_size = 0;
  /** The domain sorts (SORT_FUN only); each a Bool or bit-vector sort. */
  std::vector<Sort> d_fun_domain;
  /** The codomain sort (SORT_FUN only); a Bool or bit-vector sort. */
  Sort d_fun_codomain;
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
#ifdef MURXLA_STP_HAVE_UF
  /**
   * Construct the term standing for an uninterpreted-function declaration.
   * A declaration is a UFDeclHandle, an opaque integer identity -- not an
   * Expr -- so such a term wraps no STP expression and may only be used as
   * the first operand of Op::UF_APPLY.
   */
  StpTerm(UFDeclHandle uf_decl) : d_uf_decl(uf_decl) {}
  /** True if this term is a function declaration rather than an expression. */
  bool is_uf_decl() const { return d_uf_decl != 0; }
  /** The declaration identity (only valid when is_uf_decl()). */
  UFDeclHandle get_uf_decl() const { return d_uf_decl; }
#endif
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
  /** The wrapped STP expression (null for a function declaration). */
  Expr d_term = nullptr;
#ifdef MURXLA_STP_HAVE_UF
  /** The declaration identity; 0 unless this term is a UF declaration. */
  UFDeclHandle d_uf_decl = 0;
#endif
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

#ifdef MURXLA_STP_HAVE_ABSTRACTION_OPTS
  /**
   * The names of STP's CEGAR abstraction and UF encoding options, spelled as
   * the STP command line spells them. They are set through vc_setInterface-
   * Flags rather than the SMT-LIB option namespace, so these names exist only
   * here and in -o / --fuzz-opts.
   */
  inline static const std::string OPT_BV_EQ_ABSTRACTION = "bv-eq-abstraction";
  inline static const std::string OPT_BV_EQ_ABSTRACTION_WIDTH =
      "bv-eq-abstraction-width";
  inline static const std::string OPT_BV_EQ_REFINE_WIDTH =
      "bv-eq-refine-width";
  inline static const std::string OPT_BV_TERM_ABSTRACTION =
      "bv-term-abstraction";
  inline static const std::string OPT_UF_NARROW_RESULTS = "uf-narrow-results";
  inline static const std::string OPT_UF_INJECT_ARGS = "uf-inject-args";
#endif

#ifdef MURXLA_STP_HAVE_REFINEMENT_OPTS
  /**
   * The rest of the refinement knobs, spelled as the STP command line spells
   * them. Same namespace and the same -o / --fuzz-opts reach as the group
   * above; they are separate only because a build may have the first group
   * without this one.
   */
  inline static const std::string OPT_BV_TERM_ABSTRACTION_MULT =
      "bv-term-abstraction-mult";
  inline static const std::string OPT_BV_TERM_ABSTRACTION_ROUNDS =
      "bv-term-abstraction-rounds";
  inline static const std::string OPT_UF_LEMMAS_PER_ROUND =
      "uf-lemmas-per-round";
  inline static const std::string OPT_UF_ACKERMANN = "uf-ackermann";
  inline static const std::string OPT_UF_ACKERMANN_BUDGET =
      "uf-ackermann-budget";
  inline static const std::string OPT_UF_PHASE_HINTS = "uf-phase-hints";
  inline static const std::string OPT_DISTINCT_ORDERING = "distinct-ordering";
  inline static const std::string OPT_AIG_NODE_BUDGET = "aig-node-budget";
#endif

  StpSolver(SolverSeedGenerator& sng) : Solver(sng), d_solver(nullptr) {}
  ~StpSolver() override;

  void new_solver() override;
  void delete_solver() override;
  bool is_initialized() const override;
  const std::string get_name() const override;
  const std::string get_profile() const override;

  void configure_opmgr(OpKindManager* opmgr) const override;
  void configure_options(SolverManager* smgr) override;
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

  bool can_apply(const Op::Kind& kind,
                 const std::vector<Term>& args,
                 const std::vector<uint32_t>& indices) const override;

  bool can_get_value(const Term& term) const override;

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
#ifdef MURXLA_STP_HAVE_ABSTRACTION_OPTS
  /**
   * Push the current abstraction/UF encoding settings into the checker. The
   * settings live here rather than only in STP because reset() builds a fresh
   * checker, and a fresh checker starts from STP's own defaults again.
   */
  void apply_abstraction_opts() const;
#endif
  /**
   * Map an STP query result onto a murxla result, testing what the C API
   * promises about the values it may take.
   */
  Result to_result(int32_t res) const;
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

#ifdef MURXLA_STP_HAVE_ABSTRACTION_OPTS
  /**
   * STP's CEGAR abstraction and UF encoding settings, all on by default. The
   * two widths are set low enough that the abstractions actually engage on
   * the small bit-vectors murxla generates -- STP's own defaults abstract
   * nothing below 64 bits, which would leave these paths untested. Override
   * per run with -o, or sweep them with --fuzz-opts.
   *
   * uf-inject-args is on with the rest. It used to be off because it was an
   * under-approximation that could answer unsat for a satisfiable query, so
   * every non-injective UF was a false cross-check alarm; STP now installs
   * the injectivity assumption retractably and takes back a refutation that
   * rested on it, which makes the flag verdict-preserving and so exactly the
   * thing a cross-checked run should be exercising. Against a build that
   * predates that, pin it off with -o uf-inject-args=0.
   */
  bool d_bv_eq_abstraction              = true;
  bool d_bv_term_abstraction            = true;
  bool d_uf_narrow_results              = true;
  bool d_uf_inject_args                 = true;
  uint32_t d_bv_eq_abstraction_width    = 1;
  uint32_t d_bv_eq_refine_width         = 1;
#endif

#ifdef MURXLA_STP_HAVE_REFINEMENT_OPTS
  /**
   * The rest of the refinement knobs, at STP's own defaults except
   * bv-term-abstraction-rounds -- for the same reason the widths above are
   * lowered. That count is how many operand pairs an abstracted
   * BVMULT/BVDIV/BVMOD may be blocked on before its refinement gives up
   * enumerating and encodes the operation exactly; on bit-vectors this small
   * STP's default of 32 is rarely reached, so the escalation would go
   * untested. Four reaches it routinely, and 0 (never escalate) stays in the
   * swept range.
   *
   * aig-node-budget is 0, i.e. unlimited, because a budget that bites answers
   * unknown -- which is sound, and which the cross-checker can do nothing
   * with. It is registered so a run can ask for it deliberately.
   */
  bool d_bv_term_abstraction_mult       = true;
  uint32_t d_bv_term_abstraction_rounds = 4;
  uint32_t d_uf_lemmas_per_round        = 8;
  /** 0: auto (the default), 1: on, 2: off -- STP's own encoding. */
  uint32_t d_uf_ackermann               = 0;
  uint32_t d_uf_ackermann_budget        = 256;
  bool d_uf_phase_hints                 = false;
  bool d_distinct_ordering              = true;
  uint32_t d_aig_node_budget            = 0;
#endif
};

}  // namespace stp
}  // namespace murxla

#endif

#endif
