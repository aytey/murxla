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

#include "stp_solver.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "action.hpp"
#include "except.hpp"
#include "solver/stp/profile.hpp"
#include "theory.hpp"
#include "util.hpp"

namespace murxla {
namespace stp {

#ifdef MURXLA_STP_HAVE_UF
/** Swallow a diagnostic we asked for on purpose (see can_get_value). */
static void
ignore_diagnostic(const char*)
{
}
#endif

/* -------------------------------------------------------------------------- */
/* StpSort                                                                    */
/* -------------------------------------------------------------------------- */

size_t
StpSort::hash() const
{
  size_t res = std::hash<uint32_t>{}(static_cast<uint32_t>(d_kind));
  res = res * 31 + std::hash<uint32_t>{}(d_bv_size);
  res = res * 31 + std::hash<uint32_t>{}(d_exp_size);
  res = res * 31 + std::hash<uint32_t>{}(d_sig_size);
  if (d_kind == SORT_ARRAY)
  {
    res = res * 31 + d_index_sort->hash();
    res = res * 31 + d_element_sort->hash();
  }
  else if (d_kind == SORT_FUN)
  {
    for (const Sort& s : d_fun_domain)
    {
      res = res * 31 + s->hash();
    }
    res = res * 31 + d_fun_codomain->hash();
  }
  return res;
}

bool
StpSort::equals(const Sort& other) const
{
  StpSort* stp_sort = checked_cast<StpSort*>(other.get());
  if (!stp_sort || d_kind != stp_sort->d_kind)
  {
    return false;
  }
  if (d_kind == SORT_ARRAY)
  {
    return d_index_sort->equals(stp_sort->d_index_sort)
           && d_element_sort->equals(stp_sort->d_element_sort);
  }
  if (d_kind == SORT_FUN)
  {
    if (d_fun_domain.size() != stp_sort->d_fun_domain.size()
        || !d_fun_codomain->equals(stp_sort->d_fun_codomain))
    {
      return false;
    }
    for (size_t i = 0, n = d_fun_domain.size(); i < n; ++i)
    {
      if (!d_fun_domain[i]->equals(stp_sort->d_fun_domain[i])) return false;
    }
    return true;
  }
  return d_bv_size == stp_sort->d_bv_size && d_exp_size == stp_sort->d_exp_size
         && d_sig_size == stp_sort->d_sig_size;
}

std::string
StpSort::to_string() const
{
  if (d_kind == SORT_BOOL)
  {
    return "Bool";
  }
  if (d_kind == SORT_BV)
  {
    return "(_ BitVec " + std::to_string(d_bv_size) + ")";
  }
  if (d_kind == SORT_RM)
  {
    return "RoundingMode";
  }
  if (d_kind == SORT_FP)
  {
    return "(_ FloatingPoint " + std::to_string(d_exp_size) + " "
           + std::to_string(d_sig_size) + ")";
  }
  if (d_kind == SORT_FUN)
  {
    std::string res = "(->";
    for (const Sort& s : d_fun_domain)
    {
      res += " " + s->to_string();
    }
    return res + " " + d_fun_codomain->to_string() + ")";
  }
  assert(d_kind == SORT_ARRAY);
  return "(Array " + d_index_sort->to_string() + " " + d_element_sort->to_string()
         + ")";
}

bool
StpSort::is_array() const
{
  return d_kind == SORT_ARRAY;
}

bool
StpSort::is_bool() const
{
  return d_kind == SORT_BOOL;
}

bool
StpSort::is_bv() const
{
  return d_kind == SORT_BV;
}

bool
StpSort::is_fp() const
{
  return d_kind == SORT_FP;
}

bool
StpSort::is_fun() const
{
  return d_kind == SORT_FUN;
}

bool
StpSort::is_rm() const
{
  return d_kind == SORT_RM;
}

uint32_t
StpSort::get_bv_size() const
{
  assert(d_kind == SORT_BV);
  return d_bv_size;
}

uint32_t
StpSort::get_fp_exp_size() const
{
  assert(d_kind == SORT_FP);
  return d_exp_size;
}

uint32_t
StpSort::get_fp_sig_size() const
{
  assert(d_kind == SORT_FP);
  return d_sig_size;
}

Sort
StpSort::get_array_index_sort() const
{
  assert(d_kind == SORT_ARRAY);
  return d_index_sort;
}

Sort
StpSort::get_array_element_sort() const
{
  assert(d_kind == SORT_ARRAY);
  return d_element_sort;
}

uint32_t
StpSort::get_fun_arity() const
{
  assert(d_kind == SORT_FUN);
  return static_cast<uint32_t>(d_fun_domain.size());
}

Sort
StpSort::get_fun_codomain_sort() const
{
  assert(d_kind == SORT_FUN);
  return d_fun_codomain;
}

std::vector<Sort>
StpSort::get_fun_domain_sorts() const
{
  assert(d_kind == SORT_FUN);
  return d_fun_domain;
}

/* -------------------------------------------------------------------------- */
/* StpTerm                                                                    */
/* -------------------------------------------------------------------------- */

Expr
StpTerm::get_stp_term(Term term)
{
  StpTerm* t = checked_cast<StpTerm*>(term.get());
#ifdef MURXLA_STP_HAVE_UF
  /* A function declaration is a UFDeclHandle, not an Expr; it must never
   * reach an expression constructor. */
  assert(!t->is_uf_decl());
#endif
  return t->d_term;
}

size_t
StpTerm::hash() const
{
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl()) return static_cast<size_t>(d_uf_decl);
#endif
  return static_cast<size_t>(getExprID(d_term));
}

bool
StpTerm::equals(const Term& other) const
{
  StpTerm* stp_term = checked_cast<StpTerm*>(other.get());
  if (stp_term)
  {
#ifdef MURXLA_STP_HAVE_UF
    if (is_uf_decl() || stp_term->is_uf_decl())
    {
      return d_uf_decl == stp_term->d_uf_decl;
    }
#endif
    return getExprID(d_term) == getExprID(stp_term->d_term);
  }
  return false;
}

std::string
StpTerm::to_string() const
{
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl())
  {
    return "uf#" + std::to_string(d_uf_decl);
  }
#endif
  char* s = exprString(d_term);
  std::string res(s);
  free(s);
  return res;
}

bool
StpTerm::is_bool_value() const
{
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl()) return false;
#endif
  enum exprkind_t kind = getExprKind(d_term);
  return kind == TRUE || kind == FALSE;
}

bool
StpTerm::is_bv_value() const
{
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl()) return false;
#endif
  return getExprKind(d_term) == BVCONST;
}

bool
StpTerm::is_fp_value() const
{
  return is_value() && get_sort()->is_fp();
}

bool
StpTerm::is_rm_value() const
{
  return is_value() && get_sort()->is_rm();
}

bool
StpTerm::is_special_value(const AbsTerm::SpecialValueKind& kind) const
{
  /* For bit-vector special values, derive the answer from the actual constant
   * bit pattern rather than Murxla's leaf-kind marker. This (a) survives STP's
   * hash-consing (the marker can be dropped when a value is deduplicated to an
   * equal cached term) and (b) correctly reports small-width aliasing, e.g. a
   * 2-bit ONE (01) is also MAX_SIGNED -- mirroring how the btor/bitwuzla
   * wrappers query the solver node. */
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl()) return false;
#endif
  if (kind == AbsTerm::SPECIAL_VALUE_BV_ZERO
      || kind == AbsTerm::SPECIAL_VALUE_BV_ONE
      || kind == AbsTerm::SPECIAL_VALUE_BV_ONES
      || kind == AbsTerm::SPECIAL_VALUE_BV_MIN_SIGNED
      || kind == AbsTerm::SPECIAL_VALUE_BV_MAX_SIGNED)
  {
    if (getExprKind(d_term) != BVCONST)
    {
      return false;
    }
    char* buf         = nullptr;
    unsigned long len = 0;
    vc_printBVBitStringToBuffer(d_term, &buf, &len);
    std::string bits(buf);  // width chars, most-significant bit first
    free(buf);
    size_t w = bits.size();
    if (w == 0) return false;
    size_t ones = std::count(bits.begin(), bits.end(), '1');
    if (kind == AbsTerm::SPECIAL_VALUE_BV_ZERO) return ones == 0;
    if (kind == AbsTerm::SPECIAL_VALUE_BV_ONES) return ones == w;
    if (kind == AbsTerm::SPECIAL_VALUE_BV_ONE)
      return ones == 1 && bits[w - 1] == '1';
    if (kind == AbsTerm::SPECIAL_VALUE_BV_MIN_SIGNED)
      return bits[0] == '1' && ones == 1;
    /* SPECIAL_VALUE_BV_MAX_SIGNED: 0 1...1 */
    return bits[0] == '0' && ones == w - 1;
  }
  return AbsTerm::is_special_value(kind);
}

bool
StpTerm::is_const() const
{
#ifdef MURXLA_STP_HAVE_UF
  /* A function declaration is an uninterpreted constant of function sort. */
  if (is_uf_decl()) return true;
#endif
  /* Derive leaf kind from STP's actual expression kind rather than Murxla's
   * leaf kind: STP hash-conses and constant-folds, so a term may be replaced
   * by an equal cached term whose Murxla leaf kind differs. A RoundingMode
   * variable and a floating-point variable are both STP symbols. */
  return getExprKind(d_term) == SYMBOL;
}

bool
StpTerm::is_value() const
{
  /* A term is a value if Murxla marked it as one, or if STP intrinsically
   * represents it as a constant. The latter disjunct is required because STP
   * hash-conses/constant-folds, which can drop Murxla's VALUE leaf kind when a
   * value collides with an equal cached term (see is_const). Floating-point
   * values keep their leaf kind (FP operations never fold to a constant
   * floating-point node), so they are covered by the first disjunct. */
#ifdef MURXLA_STP_HAVE_UF
  if (is_uf_decl()) return false;
#endif
  if (get_leaf_kind() == AbsTerm::LeafKind::VALUE)
  {
    return true;
  }
  enum exprkind_t kind = getExprKind(d_term);
  return kind == BVCONST || kind == TRUE || kind == FALSE;
}

bool
StpTerm::is_var() const
{
  /* STP has no bound (quantified) variables. */
  return false;
}

/* -------------------------------------------------------------------------- */
/* StpSolver                                                                  */
/* -------------------------------------------------------------------------- */

StpSolver::~StpSolver()
{
  if (d_solver)
  {
    vc_Destroy(d_solver);
    d_solver = nullptr;
  }
}

void
StpSolver::new_solver()
{
  assert(d_solver == nullptr);
  d_solver = vc_createValidityChecker();
#ifdef MURXLA_STP_HAVE_ARRAY_EX
  /* Enable the array-extensionality decision procedure. Must be set before any
   * term is created. */
  vc_setFlag(d_solver, 'x');
#endif
#ifdef MURXLA_STP_HAVE_UF
  /* Enable uninterpreted functions (dynamic Ackermannization). Must be set
   * before the first declaration; with the flag off, vc_declareUninterpreted-
   * Function is a fatal error. Inert when nothing is declared -- the UF
   * context is created lazily on the first declaration. */
  vc_setFlag(d_solver, 'u');
#endif
}

void
StpSolver::delete_solver()
{
  assert(d_solver != nullptr);
  d_pending_assumption_pop = false;
  vc_Destroy(d_solver);
  d_solver = nullptr;
}

bool
StpSolver::is_initialized() const
{
  return d_solver != nullptr;
}

const std::string
StpSolver::get_name() const
{
  return "Stp";
}

const std::string
StpSolver::get_profile() const
{
  /* The embedded profile (profile.json) is the master-STP baseline. Adapt it
   * to the capabilities of the STP build we are linked against, detected at
   * configure time. */
#if defined(MURXLA_STP_HAVE_FP) || defined(MURXLA_STP_HAVE_ARRAY_EX) \
    || defined(MURXLA_STP_HAVE_UF)
  auto profile = nlohmann::json::parse(s_profile);

#ifdef MURXLA_STP_HAVE_FP
  /* This STP supports floating-point (symfpu). Enable THEORY_FP; STP has no
   * theory of reals, so the real-valued conversions are excluded (Murxla would
   * not generate them without THEORY_REAL, but we exclude them defensively). */
  profile["theories"]["include"].push_back("THEORY_FP");
  profile["operators"]["exclude"].push_back("OP_FP_TO_REAL");
  profile["operators"]["exclude"].push_back("OP_FP_TO_FP_FROM_REAL");
#ifndef MURXLA_STP_HAVE_ARRAY_EX
  /* FP present but no array extensionality: keep arrays bit-vector-only. The
   * wrapper only wires FP/RM array index/element sorts for the combined
   * (qf_abvbf) build, where STP's vc_arrayType accepts them. */
  for (const char* key : {"array-index", "array-element"})
  {
    profile["sorts"][key]["exclude"].push_back("SORT_FP");
    profile["sorts"][key]["exclude"].push_back("SORT_RM");
  }
#endif
#endif

#ifdef MURXLA_STP_HAVE_ARRAY_EX
  /* This STP decides array extensionality (--array-equality). Allow equality,
   * disequality and if-then-else over array terms by dropping the array
   * restrictions the master baseline imposes on them. */
  auto& sr = profile["operators"]["sort-restrictions"];
  for (const char* op : {"OP_EQUAL", "OP_DISTINCT", "OP_ITE"})
  {
    if (sr.contains(op))
    {
      sr.erase(op);
    }
  }
#endif

#ifdef MURXLA_STP_HAVE_UF
  /* This STP decides quantifier-free uninterpreted functions
   * (--uninterpreted-functions). Enable THEORY_UF, but constrain it to what
   * vc_declareUninterpretedFunction accepts. Arrays are refused by design --
   * an uninterpreted function is decided by comparing concrete argument
   * values, and a counterexample gives an array only as a partial map -- and
   * a function sort is not a term sort at all. */
  profile["theories"]["include"].push_back("THEORY_UF");
  for (const char* key : {"fun-sort-domain", "fun-sort-codomain"})
  {
    for (const char* sk :
         {"SORT_ARRAY", "SORT_FUN", "SORT_UNINTERPRETED"})
    {
      profile["sorts"][key]["exclude"].push_back(sk);
    }
#ifndef MURXLA_STP_HAVE_FP
    /* Without symfpu there are no FP/RM sorts to put in a signature. When it
     * is present they are admitted: a float position is compared by value, so
     * every NaN is one argument while -0 and +0 stay distinct, and a
     * RoundingMode position is pinned to the five modes its carrier encodes. */
    for (const char* sk : {"SORT_FP", "SORT_RM"})
    {
      profile["sorts"][key]["exclude"].push_back(sk);
    }
#endif
  }
  /* THEORY_UF also registers SORT_UNINTERPRETED; STP has no uninterpreted
   * sorts, so drop it everywhere. */
  profile["sorts"]["exclude"].push_back("SORT_UNINTERPRETED");
  /* A function symbol has no model value of its own. */
  profile["sorts"]["get-value"]["exclude"].push_back("SORT_FUN");
  /* A declaration handle is not a term: it may only appear as the first
   * operand of OP_UF_APPLY. STP has no way to build an if-then-else over two
   * function symbols, nor to compare them, so keep the generator off those
   * (this must come after the array-extensionality block above, which erases
   * these keys wholesale). */
  for (const char* op : {"OP_ITE", "OP_EQUAL", "OP_DISTINCT"})
  {
    profile["operators"]["sort-restrictions"][op].push_back("SORT_FUN");
  }
#endif

  return profile.dump();
#else
  return s_profile;
#endif
}

void
StpSolver::configure_opmgr(OpKindManager* opmgr) const
{
  opmgr->add_op_kind(OP_UADDO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
  opmgr->add_op_kind(OP_SADDO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
  opmgr->add_op_kind(OP_USUBO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
  opmgr->add_op_kind(OP_SSUBO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
  opmgr->add_op_kind(OP_UMULO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
  opmgr->add_op_kind(OP_SMULO, 2, 0, SORT_BOOL, {SORT_BV}, THEORY_BV);
}

void
StpSolver::disable_unsupported_actions(FSM* fsm) const
{
  /* STP's C API has no way to define functions/macros. */
  fsm->disable_action(ActionMkFun::s_name);
  /* No reset-assertions equivalent (reset() recreates the solver). */
  fsm->disable_action(ActionResetAssertions::s_name);
  /* No parametric sorts. */
  fsm->disable_action(ActionInstantiateSort::s_name);
}

bool
StpSolver::is_unsat_assumption(const Term& t) const
{
  return true;
}

std::string
StpSolver::get_option_name_incremental() const
{
  return "incremental";
}

std::string
StpSolver::get_option_name_model_gen() const
{
  return "produce-models";
}

std::string
StpSolver::get_option_name_unsat_assumptions() const
{
  return "produce-unsat-assumptions";
}

std::string
StpSolver::get_option_name_unsat_cores() const
{
  return "produce-unsat-cores";
}

bool
StpSolver::option_incremental_enabled() const
{
  return d_incremental;
}

bool
StpSolver::option_model_gen_enabled() const
{
  return d_model_gen;
}

bool
StpSolver::option_unsat_assumptions_enabled() const
{
  /* STP has no notion of unsat assumptions. */
  return false;
}

bool
StpSolver::option_unsat_cores_enabled() const
{
  /* STP has no support for unsat cores. */
  return false;
}

void
StpSolver::set_opt(const std::string& opt, const std::string& value)
{
  if (opt == get_option_name_incremental())
  {
    d_incremental = value == "true";
#ifdef MURXLA_STP_HAVE_INCREMENTAL
    /* Put STP in incremental mode from the very first query, not just from the
     * first vc_push: with 'i' set, the persistent incremental driver handles
     * every solve (see docs/incremental-solving.rst). The flag is sticky in
     * STP, which is fine -- we only ever force it on. Set before any term is
     * created, which the FSM guarantees (options precede term construction). */
    if (d_incremental)
      vc_setFlag(d_solver, 'i');
#endif
  }
  else if (opt == get_option_name_model_gen())
  {
    d_model_gen = value == "true";
  }
  /* All other options (including produce-unsat-assumptions and
   * produce-unsat-cores, which STP does not support and which thus remain
   * disabled) are ignored. */
}

Type
StpSolver::get_stp_type(Sort sort) const
{
  StpSort* stp_sort = checked_cast<StpSort*>(sort.get());
  assert(stp_sort);
  switch (stp_sort->d_kind)
  {
    case SORT_BOOL: return vc_boolType(d_solver);
    case SORT_BV:
      return vc_bvType(d_solver, static_cast<int32_t>(stp_sort->d_bv_size));
    case SORT_ARRAY:
      /* Index and element may each be BV, FP or RM; recurse to build each. */
      return vc_arrayType(d_solver,
                          get_stp_type(stp_sort->d_index_sort),
                          get_stp_type(stp_sort->d_element_sort));
#ifdef MURXLA_STP_HAVE_FP
    case SORT_FP:
      return vc_fpType(d_solver,
                       static_cast<int32_t>(stp_sort->d_exp_size),
                       static_cast<int32_t>(stp_sort->d_sig_size));
    case SORT_RM: return vc_fpRoundingModeType(d_solver);
#endif
    default:
      MURXLA_CHECK_CONFIG(false)
          << "unsupported sort kind '" << stp_sort->d_kind
          << "' as argument to StpSolver::get_stp_type";
  }
  return nullptr;
}

std::vector<Expr>
StpSolver::terms_to_stp_terms(const std::vector<Term>& terms) const
{
  std::vector<Expr> res;
  for (const Term& t : terms)
  {
    res.push_back(StpTerm::get_stp_term(t));
  }
  return res;
}

void
StpSolver::pop_pending_assumption_scope()
{
  if (d_pending_assumption_pop)
  {
    d_pending_assumption_pop = false;
    vc_pop(d_solver);
  }
}

Term
StpSolver::mk_var(Sort sort, const std::string& name)
{
  MURXLA_CHECK_CONFIG(false) << "StpSolver: quantified variables not supported";
  return nullptr;
}

Term
StpSolver::mk_const(Sort sort, const std::string& name)
{
  /* STP requires variable names to consist of alphanumeric characters and
   * underscores only (anything else is undefined behavior). */
  std::string symbol;
  for (char c : name)
  {
    symbol += (isalnum(c) || c == '_') ? c : '_';
  }
  if (symbol.empty())
  {
    symbol = "_x" + std::to_string(d_num_symbols++);
  }
#ifdef MURXLA_STP_HAVE_UF
  if (sort->is_fun())
  {
    /* Declare an uninterpreted function. STP fatal-errors on a duplicate
     * name, and the sanitisation above maps every non-alphanumeric character
     * to '_', so distinct Murxla symbols collide readily -- suffix
     * unconditionally to make the name unique within this context. */
    symbol += "_uf" + std::to_string(d_num_symbols++);
    std::vector<Sort> domain_sorts = sort->get_fun_domain_sorts();
    std::vector<Type> domain;
    for (const Sort& s : domain_sorts)
    {
      domain.push_back(get_stp_type(s));
    }
    assert(!domain.empty());
    UFDeclHandle res = vc_declareUninterpretedFunction(
        d_solver,
        symbol.c_str(),
        domain.data(),
        domain.size(),
        get_stp_type(sort->get_fun_codomain_sort()));
    /* Validation failures are nonfatal and return zero; the generator only
     * ever asks for signatures STP accepts, so a zero here is a wrapper bug
     * worth reporting rather than ignoring. */
    MURXLA_TEST(res != 0);
    auto res_term = std::shared_ptr<StpTerm>(new StpTerm(res));
    /* A declaration is an opaque identity carrying no sort information;
     * record the Murxla sort so get_sort never has to recover it. */
    res_term->set_sort(sort);
    return res_term;
  }
#endif
#ifdef MURXLA_STP_HAVE_FP
  if (sort->is_rm())
  {
    /* A RoundingMode variable: STP has no rm type handle, but this dedicated
     * entry point makes a proper RoundingMode symbol (a 5-bit variable pinned
     * to the five legal one-hot encodings, with the constraint asserted at the
     * current assertion level). */
    Expr res = vc_fpRoundingModeVar(d_solver, symbol.c_str());
    return std::shared_ptr<StpTerm>(new StpTerm(res));
  }
#endif
  Expr res = vc_varExpr(d_solver, symbol.c_str(), get_stp_type(sort));
  return std::shared_ptr<StpTerm>(new StpTerm(res));
}

Term
StpSolver::mk_fun(const std::string& name,
                  const std::vector<Term>& args,
                  Term body)
{
  MURXLA_CHECK_CONFIG(false) << "StpSolver: functions not supported";
  return nullptr;
}

Term
StpSolver::mk_value(Sort sort, bool value)
{
  MURXLA_CHECK_CONFIG(sort->is_bool())
      << "unexpected sort of kind '" << sort->get_kind()
      << "' as argument to StpSolver::mk_value, expected Boolean sort";
  Expr res = value ? vc_trueExpr(d_solver) : vc_falseExpr(d_solver);
  return std::shared_ptr<StpTerm>(new StpTerm(res));
}

Term
StpSolver::mk_value(Sort sort, const std::string& value)
{
#ifdef MURXLA_STP_HAVE_FP
  MURXLA_CHECK_CONFIG(sort->is_fp())
      << "unexpected sort of kind '" << sort->get_kind()
      << "' as argument to StpSolver::mk_value, expected floating-point sort";
  /* value is the concatenated IEEE bit pattern (sign : exponent : significand)
   * of width eb+sb. */
  uint32_t eb = sort->get_fp_exp_size();
  uint32_t sb = sort->get_fp_sig_size();
  MURXLA_TEST(value.size() == eb + sb);
  Expr bv  = vc_bvConstExprFromStr(d_solver, value.c_str());
  Expr res = vc_fpConstFromBits(
      d_solver, static_cast<int32_t>(eb), static_cast<int32_t>(sb), bv);
  return std::shared_ptr<StpTerm>(new StpTerm(res));
#else
  MURXLA_CHECK_CONFIG(false)
      << "StpSolver::mk_value: this STP build has no floating-point support";
  (void) sort;
  (void) value;
  return nullptr;
#endif
}

namespace {
std::string
hex_char_to_bin(char c)
{
  switch (tolower(c))
  {
    case '0': return "0000";
    case '1': return "0001";
    case '2': return "0010";
    case '3': return "0011";
    case '4': return "0100";
    case '5': return "0101";
    case '6': return "0110";
    case '7': return "0111";
    case '8': return "1000";
    case '9': return "1001";
    case 'a': return "1010";
    case 'b': return "1011";
    case 'c': return "1100";
    case 'd': return "1101";
    case 'e': return "1110";
    default: assert(tolower(c) == 'f'); return "1111";
  }
}
}  // namespace

Term
StpSolver::mk_value(Sort sort, const std::string& value, Base base)
{
  MURXLA_CHECK_CONFIG(sort->is_bv())
      << "unexpected sort of kind '" << sort->get_kind()
      << "' as argument to StpSolver::mk_value, expected bit-vector sort";

  uint32_t bw = sort->get_bv_size();
  Expr res    = nullptr;

  switch (base)
  {
    case DEC:
    {
      bool negate = !value.empty() && value[0] == '-';
      const std::string dec = negate ? value.substr(1) : value;
      res                   = vc_bvConstExprFromDecStr(
          d_solver, static_cast<int32_t>(bw), dec.c_str());
      if (negate)
      {
        res = vc_bvUMinusExpr(d_solver, res);
      }
    }
    break;

    case HEX:
    {
      std::string bin;
      for (char c : value)
      {
        bin += hex_char_to_bin(c);
      }
      if (bin.size() > bw)
      {
        size_t n_trim = bin.size() - bw;
        MURXLA_TEST(bin.substr(0, n_trim).find('1') == std::string::npos);
        bin = bin.substr(n_trim);
      }
      else if (bin.size() < bw)
      {
        bin = std::string(bw - bin.size(), '0') + bin;
      }
      res = vc_bvConstExprFromStr(d_solver, bin.c_str());
    }
    break;

    default:
    {
      assert(base == BIN);
      MURXLA_TEST(value.size() == bw);
      res = vc_bvConstExprFromStr(d_solver, value.c_str());
    }
  }
  return std::shared_ptr<StpTerm>(new StpTerm(res));
}

Term
StpSolver::mk_special_value(Sort sort, const AbsTerm::SpecialValueKind& value)
{
#ifdef MURXLA_STP_HAVE_FP
  if (sort->is_fp())
  {
    Type fp = get_stp_type(sort);
    Expr res;
    if (value == AbsTerm::SPECIAL_VALUE_FP_POS_INF)
    {
      res = vc_fpPlusInfinity(d_solver, fp);
    }
    else if (value == AbsTerm::SPECIAL_VALUE_FP_NEG_INF)
    {
      res = vc_fpMinusInfinity(d_solver, fp);
    }
    else if (value == AbsTerm::SPECIAL_VALUE_FP_POS_ZERO)
    {
      res = vc_fpPlusZero(d_solver, fp);
    }
    else if (value == AbsTerm::SPECIAL_VALUE_FP_NEG_ZERO)
    {
      res = vc_fpMinusZero(d_solver, fp);
    }
    else
    {
      MURXLA_CHECK_CONFIG(value == AbsTerm::SPECIAL_VALUE_FP_NAN)
          << "unexpected floating-point special value '" << value << "'";
      res = vc_fpNaN(d_solver, fp);
    }
    return std::shared_ptr<StpTerm>(new StpTerm(res));
  }
  if (sort->is_rm())
  {
    enum VCRoundingMode mode;
    if (value == AbsTerm::SPECIAL_VALUE_RM_RNE)
    {
      mode = VC_RM_RNE;
    }
    else if (value == AbsTerm::SPECIAL_VALUE_RM_RNA)
    {
      mode = VC_RM_RNA;
    }
    else if (value == AbsTerm::SPECIAL_VALUE_RM_RTP)
    {
      mode = VC_RM_RTP;
    }
    else if (value == AbsTerm::SPECIAL_VALUE_RM_RTN)
    {
      mode = VC_RM_RTN;
    }
    else
    {
      MURXLA_CHECK_CONFIG(value == AbsTerm::SPECIAL_VALUE_RM_RTZ)
          << "unexpected rounding-mode special value '" << value << "'";
      mode = VC_RM_RTZ;
    }
    Expr res = vc_fpRoundingMode(d_solver, mode);
    return std::shared_ptr<StpTerm>(new StpTerm(res));
  }
#endif

  MURXLA_CHECK_CONFIG(sort->is_bv())
      << "unexpected sort of kind '" << sort->get_kind()
      << "' as argument to StpSolver::mk_special_value, expected bit-vector "
         "sort";

  uint32_t bw = sort->get_bv_size();
  std::string bin;

  if (value == AbsTerm::SPECIAL_VALUE_BV_ZERO)
  {
    bin = std::string(bw, '0');
  }
  else if (value == AbsTerm::SPECIAL_VALUE_BV_ONE)
  {
    bin = std::string(bw - 1, '0') + "1";
  }
  else if (value == AbsTerm::SPECIAL_VALUE_BV_ONES)
  {
    bin = std::string(bw, '1');
  }
  else if (value == AbsTerm::SPECIAL_VALUE_BV_MIN_SIGNED)
  {
    bin = "1" + std::string(bw - 1, '0');
  }
  else
  {
    MURXLA_CHECK_CONFIG(value == AbsTerm::SPECIAL_VALUE_BV_MAX_SIGNED)
        << "unexpected special value '" << value
        << "' as argument to StpSolver::mk_special_value";
    bin = "0" + std::string(bw - 1, '1');
  }
  Expr res = vc_bvConstExprFromStr(d_solver, bin.c_str());
  return std::shared_ptr<StpTerm>(new StpTerm(res));
}

Sort
StpSolver::mk_sort(SortKind kind)
{
#ifdef MURXLA_STP_HAVE_FP
  if (kind == SORT_RM)
  {
    return std::shared_ptr<StpSort>(new StpSort(SORT_RM));
  }
#endif
  MURXLA_CHECK_CONFIG(kind == SORT_BOOL)
      << "unsupported sort kind '" << kind
      << "' as argument to StpSolver::mk_sort, expected '" << SORT_BOOL << "'";
  return std::shared_ptr<StpSort>(new StpSort());
}

Sort
StpSolver::mk_sort(SortKind kind, uint32_t size)
{
  MURXLA_CHECK_CONFIG(kind == SORT_BV)
      << "unsupported sort kind '" << kind
      << "' as argument to StpSolver::mk_sort, expected '" << SORT_BV << "'";
  return std::shared_ptr<StpSort>(new StpSort(size));
}

Sort
StpSolver::mk_sort(SortKind kind, uint32_t esize, uint32_t ssize)
{
  MURXLA_CHECK_CONFIG(kind == SORT_FP)
      << "unsupported sort kind '" << kind
      << "' as argument to StpSolver::mk_sort, expected '" << SORT_FP << "'";
  return std::shared_ptr<StpSort>(new StpSort(SORT_FP, esize, ssize));
}

Sort
StpSolver::mk_sort(SortKind kind, const std::vector<Sort>& sorts)
{
#ifdef MURXLA_STP_HAVE_UF
  if (kind == SORT_FUN)
  {
    /* sorts is {domain_1, ..., domain_n, codomain}; STP requires arity >= 1
     * (a zero-arity function is an ordinary variable) and every domain and
     * codomain sort to be Bool, RoundingMode, FloatingPoint or a
     * nonzero-width bit-vector. Arrays and function sorts are refused. */
    assert(sorts.size() >= 2);
    for (const Sort& s : sorts)
    {
      bool ok = s->is_bool() || (s->is_bv() && s->get_bv_size() > 0);
#ifdef MURXLA_STP_HAVE_FP
      ok = ok || s->is_fp() || s->is_rm();
#endif
      MURXLA_CHECK_CONFIG(ok)
          << "STP uninterpreted-function domain and codomain sorts must be "
             "Bool, RoundingMode, FloatingPoint or a nonzero-width bit-vector";
    }
    std::vector<Sort> domain(sorts.begin(), sorts.end() - 1);
    return std::shared_ptr<StpSort>(new StpSort(domain, sorts.back()));
  }
#endif
  MURXLA_CHECK_CONFIG(kind == SORT_ARRAY)
      << "unsupported sort kind '" << kind
      << "' as argument to StpSolver::mk_sort, expected '" << SORT_ARRAY
      << "'";
  assert(sorts.size() == 2);
#if defined(MURXLA_STP_HAVE_FP) && defined(MURXLA_STP_HAVE_ARRAY_EX)
  /* Combined (qf_abvbf) build: index and element may each be BV, FP or RM,
   * matching STP's generalized vc_arrayType. */
  for (const Sort& s : sorts)
  {
    MURXLA_CHECK_CONFIG(s->is_bv() || s->is_fp() || s->is_rm())
        << "STP array index/element sorts must be bit-vector, floating-point "
           "or RoundingMode";
  }
#else
  MURXLA_CHECK_CONFIG(sorts[0]->is_bv() && sorts[1]->is_bv())
      << "STP only supports bit-vector index and element sorts for arrays";
#endif
  return std::shared_ptr<StpSort>(new StpSort(sorts[0], sorts[1]));
}

Expr
StpSolver::mk_term_left_assoc(std::vector<Expr>& args,
                              const std::function<Expr(Expr, Expr)>& fun) const
{
  assert(args.size() >= 2);
  Expr res = fun(args[0], args[1]);
  for (size_t i = 2, n = args.size(); i < n; ++i)
  {
    res = fun(res, args[i]);
  }
  return res;
}

Expr
StpSolver::mk_term_right_assoc(std::vector<Expr>& args,
                               const std::function<Expr(Expr, Expr)>& fun) const
{
  assert(args.size() >= 2);
  size_t n = args.size();
  Expr res = fun(args[n - 2], args[n - 1]);
  for (size_t i = 3; i <= n; ++i)
  {
    res = fun(args[n - i], res);
  }
  return res;
}

Expr
StpSolver::mk_term_pairwise(std::vector<Expr>& args,
                            const std::function<Expr(Expr, Expr)>& fun) const
{
  assert(args.size() >= 2);
  std::vector<Expr> tmp;
  for (size_t i = 0, n = args.size(); i < n - 1; ++i)
  {
    for (size_t j = i + 1; j < n; ++j)
    {
      tmp.push_back(fun(args[i], args[j]));
    }
  }
  if (tmp.size() == 1)
  {
    return tmp[0];
  }
  return vc_andExprN(d_solver, tmp.data(), static_cast<int32_t>(tmp.size()));
}

Expr
StpSolver::mk_term_chained(std::vector<Expr>& args,
                           const std::function<Expr(Expr, Expr)>& fun) const
{
  assert(args.size() >= 2);
  std::vector<Expr> tmp;
  for (size_t i = 0, n = args.size(); i < n - 1; ++i)
  {
    tmp.push_back(fun(args[i], args[i + 1]));
  }
  if (tmp.size() == 1)
  {
    return tmp[0];
  }
  return vc_andExprN(d_solver, tmp.data(), static_cast<int32_t>(tmp.size()));
}

#ifdef MURXLA_STP_HAVE_FP
bool
StpSolver::is_fp_kind(const Op::Kind& kind)
{
  static const std::unordered_set<Op::Kind> s_fp_kinds = {
      Op::FP_ABS,        Op::FP_NEG,           Op::FP_ADD,
      Op::FP_SUB,        Op::FP_MUL,           Op::FP_DIV,
      Op::FP_FMA,        Op::FP_SQRT,          Op::FP_RTI,
      Op::FP_REM,        Op::FP_MIN,           Op::FP_MAX,
      Op::FP_FP,         Op::FP_EQ,            Op::FP_LEQ,
      Op::FP_LT,         Op::FP_GEQ,           Op::FP_GT,
      Op::FP_IS_NORMAL,  Op::FP_IS_SUBNORMAL,  Op::FP_IS_ZERO,
      Op::FP_IS_INF,     Op::FP_IS_NAN,        Op::FP_IS_NEG,
      Op::FP_IS_POS,     Op::FP_TO_FP_FROM_BV, Op::FP_TO_FP_FROM_SBV,
      Op::FP_TO_FP_FROM_UBV, Op::FP_TO_FP_FROM_FP, Op::FP_TO_SBV,
      Op::FP_TO_UBV,
  };
  return s_fp_kinds.find(kind) != s_fp_kinds.end();
}

Expr
StpSolver::mk_term_fp(const Op::Kind& kind,
                      std::vector<Expr>& args,
                      const std::vector<uint32_t>& indices) const
{
  VC vc = d_solver;

  /* Unary and rounding-mode arithmetic (rm is always args[0] when present). */
  if (kind == Op::FP_ABS) return vc_fpAbsExpr(vc, args[0]);
  if (kind == Op::FP_NEG) return vc_fpNegExpr(vc, args[0]);
  if (kind == Op::FP_ADD) return vc_fpAddExpr(vc, args[0], args[1], args[2]);
  if (kind == Op::FP_SUB) return vc_fpSubExpr(vc, args[0], args[1], args[2]);
  if (kind == Op::FP_MUL) return vc_fpMulExpr(vc, args[0], args[1], args[2]);
  if (kind == Op::FP_DIV) return vc_fpDivExpr(vc, args[0], args[1], args[2]);
  if (kind == Op::FP_FMA)
    return vc_fpFMAExpr(vc, args[0], args[1], args[2], args[3]);
  if (kind == Op::FP_SQRT) return vc_fpSqrtExpr(vc, args[0], args[1]);
  if (kind == Op::FP_RTI)
    return vc_fpRoundToIntegralExpr(vc, args[0], args[1]);
  if (kind == Op::FP_REM) return vc_fpRemExpr(vc, args[0], args[1]);
  if (kind == Op::FP_MIN) return vc_fpMinExpr(vc, args[0], args[1]);
  if (kind == Op::FP_MAX) return vc_fpMaxExpr(vc, args[0], args[1]);

  /* (fp sign exp sig): pack the three bit-vectors and reinterpret as FP. */
  if (kind == Op::FP_FP)
  {
    int32_t eb    = getBVLength(args[1]);
    int32_t sb    = getBVLength(args[2]) + 1;
    Expr packed   = vc_bvConcatExpr(
        vc, args[0], vc_bvConcatExpr(vc, args[1], args[2]));
    return vc_fpToFPFromIEEEBV(vc, eb, sb, packed);
  }

  /* Chainable predicates. */
  if (kind == Op::FP_EQ)
    return mk_term_chained(
        args, [vc](Expr l, Expr r) { return vc_fpEqExpr(vc, l, r); });
  if (kind == Op::FP_LEQ)
    return mk_term_chained(
        args, [vc](Expr l, Expr r) { return vc_fpLeqExpr(vc, l, r); });
  if (kind == Op::FP_LT)
    return mk_term_chained(
        args, [vc](Expr l, Expr r) { return vc_fpLtExpr(vc, l, r); });
  if (kind == Op::FP_GEQ)
    return mk_term_chained(
        args, [vc](Expr l, Expr r) { return vc_fpGeqExpr(vc, l, r); });
  if (kind == Op::FP_GT)
    return mk_term_chained(
        args, [vc](Expr l, Expr r) { return vc_fpGtExpr(vc, l, r); });

  /* Classification predicates. */
  if (kind == Op::FP_IS_NORMAL) return vc_fpIsNormalExpr(vc, args[0]);
  if (kind == Op::FP_IS_SUBNORMAL) return vc_fpIsSubnormalExpr(vc, args[0]);
  if (kind == Op::FP_IS_ZERO) return vc_fpIsZeroExpr(vc, args[0]);
  if (kind == Op::FP_IS_INF) return vc_fpIsInfiniteExpr(vc, args[0]);
  if (kind == Op::FP_IS_NAN) return vc_fpIsNaNExpr(vc, args[0]);
  if (kind == Op::FP_IS_NEG) return vc_fpIsNegativeExpr(vc, args[0]);
  if (kind == Op::FP_IS_POS) return vc_fpIsPositiveExpr(vc, args[0]);

  /* Conversions. */
  if (kind == Op::FP_TO_FP_FROM_BV)
    return vc_fpToFPFromIEEEBV(vc,
                               static_cast<int32_t>(indices[0]),
                               static_cast<int32_t>(indices[1]),
                               args[0]);
  if (kind == Op::FP_TO_FP_FROM_SBV)
    return vc_fpToFPFromSignedBV(vc,
                                 static_cast<int32_t>(indices[0]),
                                 static_cast<int32_t>(indices[1]),
                                 args[0],
                                 args[1]);
  if (kind == Op::FP_TO_FP_FROM_UBV)
    return vc_fpToFPFromUnsignedBV(vc,
                                   static_cast<int32_t>(indices[0]),
                                   static_cast<int32_t>(indices[1]),
                                   args[0],
                                   args[1]);
  if (kind == Op::FP_TO_FP_FROM_FP)
    return vc_fpToFPFromFP(vc,
                           static_cast<int32_t>(indices[0]),
                           static_cast<int32_t>(indices[1]),
                           args[0],
                           args[1]);
  if (kind == Op::FP_TO_SBV)
    return vc_fpToSBVExpr(
        vc, static_cast<int32_t>(indices[0]), args[0], args[1]);
  MURXLA_CHECK_CONFIG(kind == Op::FP_TO_UBV)
      << "StpSolver: unsupported floating-point operator '" << kind << "'";
  return vc_fpToUBVExpr(
      vc, static_cast<int32_t>(indices[0]), args[0], args[1]);
}
#endif

Term
StpSolver::mk_term(const Op::Kind& kind,
                   const std::vector<Term>& args,
                   const std::vector<uint32_t>& indices,
                   const std::vector<std::string>& special_args)
{
#ifdef MURXLA_STP_HAVE_UF
  if (kind == Op::UF_APPLY)
  {
    /* args[0] is the declaration (a UFDeclHandle, not an Expr, so it must be
     * kept out of terms_to_stp_terms); args[1..] are the actuals. */
    assert(args.size() >= 2);
    StpTerm* decl = checked_cast<StpTerm*>(args[0].get());
    assert(decl->is_uf_decl());
    std::vector<Expr> actuals;
    for (size_t i = 1, n = args.size(); i < n; ++i)
    {
      actuals.push_back(StpTerm::get_stp_term(args[i]));
    }
    Expr uf_res = vc_applyUninterpretedFunction(
        d_solver, decl->get_uf_decl(), actuals.data(), actuals.size());
    /* Arity/sort mismatches are nonfatal and return NULL; the generator only
     * builds well-typed applications, so NULL means a wrapper bug. */
    MURXLA_TEST(uf_res != nullptr);
    return std::shared_ptr<StpTerm>(new StpTerm(uf_res));
  }
#endif
  std::vector<Expr> stp_args = terms_to_stp_terms(args);
  size_t n_args              = stp_args.size();
  Expr res                   = nullptr;
  VC vc                      = d_solver;

  auto is_bool_args = [&stp_args]() {
    return getType(stp_args[0]) == BOOLEAN_TYPE;
  };
  auto eq_fun = [this, vc, &is_bool_args]() -> std::function<Expr(Expr, Expr)> {
    if (is_bool_args())
    {
      return [vc](Expr l, Expr r) { return vc_iffExpr(vc, l, r); };
    }
    return [vc](Expr l, Expr r) { return vc_eqExpr(vc, l, r); };
  };

  if (kind == Op::ITE)
  {
    assert(n_args == 3);
    res = vc_iteExpr(vc, stp_args[0], stp_args[1], stp_args[2]);
  }
  else if (kind == Op::EQUAL)
  {
    res = mk_term_chained(stp_args, eq_fun());
  }
  else if (kind == Op::DISTINCT)
  {
    auto eq = eq_fun();
    res     = mk_term_pairwise(stp_args, [vc, &eq](Expr l, Expr r) {
      return vc_notExpr(vc, eq(l, r));
    });
  }
  /* Boolean */
  else if (kind == Op::AND)
  {
    res = vc_andExprN(vc, stp_args.data(), static_cast<int32_t>(n_args));
  }
  else if (kind == Op::OR)
  {
    res = vc_orExprN(vc, stp_args.data(), static_cast<int32_t>(n_args));
  }
  else if (kind == Op::NOT)
  {
    assert(n_args == 1);
    res = vc_notExpr(vc, stp_args[0]);
  }
  else if (kind == Op::XOR)
  {
    assert(n_args == 2);
    res = vc_xorExpr(vc, stp_args[0], stp_args[1]);
  }
  else if (kind == Op::IMPLIES)
  {
    res = mk_term_right_assoc(stp_args, [vc](Expr l, Expr r) {
      return vc_impliesExpr(vc, l, r);
    });
  }
  else if (kind == Op::IFF)
  {
    assert(n_args == 2);
    res = vc_iffExpr(vc, stp_args[0], stp_args[1]);
  }
  /* Arrays */
  else if (kind == Op::ARRAY_SELECT)
  {
    assert(n_args == 2);
    res = vc_readExpr(vc, stp_args[0], stp_args[1]);
  }
  else if (kind == Op::ARRAY_STORE)
  {
    assert(n_args == 3);
    res = vc_writeExpr(vc, stp_args[0], stp_args[1], stp_args[2]);
  }
#ifdef MURXLA_STP_HAVE_FP
  else if (is_fp_kind(kind))
  {
    res = mk_term_fp(kind, stp_args, indices);
  }
#endif
  /* Bit-vectors */
  else
  {
    int32_t bw = getBVLength(stp_args[0]);

    if (kind == Op::BV_CONCAT)
    {
      res = mk_term_left_assoc(stp_args, [vc](Expr l, Expr r) {
        return vc_bvConcatExpr(vc, l, r);
      });
    }
    else if (kind == Op::BV_ADD)
    {
      res = vc_bvPlusExprN(
          vc, bw, stp_args.data(), static_cast<int32_t>(n_args));
    }
    else if (kind == Op::BV_SUB)
    {
      assert(n_args == 2);
      res = vc_bvMinusExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_MULT)
    {
      res = mk_term_left_assoc(stp_args, [vc, bw](Expr l, Expr r) {
        return vc_bvMultExpr(vc, bw, l, r);
      });
    }
    else if (kind == Op::BV_NEG)
    {
      assert(n_args == 1);
      res = vc_bvUMinusExpr(vc, stp_args[0]);
    }
    else if (kind == Op::BV_NOT)
    {
      assert(n_args == 1);
      res = vc_bvNotExpr(vc, stp_args[0]);
    }
    else if (kind == Op::BV_AND)
    {
      res = mk_term_left_assoc(stp_args, [vc](Expr l, Expr r) {
        return vc_bvAndExpr(vc, l, r);
      });
    }
    else if (kind == Op::BV_OR)
    {
      res = mk_term_left_assoc(stp_args, [vc](Expr l, Expr r) {
        return vc_bvOrExpr(vc, l, r);
      });
    }
    else if (kind == Op::BV_XOR)
    {
      res = mk_term_left_assoc(stp_args, [vc](Expr l, Expr r) {
        return vc_bvXorExpr(vc, l, r);
      });
    }
    else if (kind == Op::BV_NAND)
    {
      assert(n_args == 2);
      res = vc_bvNandExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_NOR)
    {
      assert(n_args == 2);
      res = vc_bvNorExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_XNOR)
    {
      assert(n_args == 2);
      res = vc_bvXnorExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_COMP)
    {
      assert(n_args == 2);
      res = vc_iteExpr(vc,
                       vc_eqExpr(vc, stp_args[0], stp_args[1]),
                       vc_bvConstExprFromInt(vc, 1, 1),
                       vc_bvConstExprFromInt(vc, 1, 0));
    }
    else if (kind == Op::BV_UDIV)
    {
      assert(n_args == 2);
      res = vc_bvDivExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_UREM)
    {
      assert(n_args == 2);
      res = vc_bvModExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SDIV)
    {
      assert(n_args == 2);
      res = vc_sbvDivExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SREM)
    {
      assert(n_args == 2);
      res = vc_sbvRemExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SMOD)
    {
      assert(n_args == 2);
      res = vc_sbvModExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SHL)
    {
      assert(n_args == 2);
      res = vc_bvLeftShiftExprExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_LSHR)
    {
      assert(n_args == 2);
      res = vc_bvRightShiftExprExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_ASHR)
    {
      assert(n_args == 2);
      res = vc_bvSignedRightShiftExprExpr(vc, bw, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_ULT)
    {
      assert(n_args == 2);
      res = vc_bvLtExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_ULE)
    {
      assert(n_args == 2);
      res = vc_bvLeExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_UGT)
    {
      assert(n_args == 2);
      res = vc_bvGtExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_UGE)
    {
      assert(n_args == 2);
      res = vc_bvGeExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SLT)
    {
      assert(n_args == 2);
      res = vc_sbvLtExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SLE)
    {
      assert(n_args == 2);
      res = vc_sbvLeExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SGT)
    {
      assert(n_args == 2);
      res = vc_sbvGtExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_SGE)
    {
      assert(n_args == 2);
      res = vc_sbvGeExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == Op::BV_EXTRACT)
    {
      assert(n_args == 1);
      assert(indices.size() == 2);
      res = vc_bvExtract(vc,
                         stp_args[0],
                         static_cast<int32_t>(indices[0]),
                         static_cast<int32_t>(indices[1]));
    }
    else if (kind == Op::BV_SIGN_EXTEND)
    {
      assert(n_args == 1);
      assert(indices.size() == 1);
      res = vc_bvSignExtend(
          vc, stp_args[0], bw + static_cast<int32_t>(indices[0]));
    }
    else if (kind == Op::BV_ZERO_EXTEND)
    {
      assert(n_args == 1);
      assert(indices.size() == 1);
      res = vc_bvZeroExtend(
          vc, stp_args[0], bw + static_cast<int32_t>(indices[0]));
    }
    else if (kind == Op::BV_ROTATE_LEFT || kind == Op::BV_ROTATE_RIGHT)
    {
      assert(n_args == 1);
      assert(indices.size() == 1);
      Expr e    = stp_args[0];
      int32_t n = static_cast<int32_t>(indices[0]) % bw;
      if (n == 0)
      {
        res = vc_bvExtract(vc, e, bw - 1, 0);
      }
      else if (kind == Op::BV_ROTATE_LEFT)
      {
        res = vc_bvConcatExpr(vc,
                              vc_bvExtract(vc, e, bw - n - 1, 0),
                              vc_bvExtract(vc, e, bw - 1, bw - n));
      }
      else
      {
        res = vc_bvConcatExpr(vc,
                              vc_bvExtract(vc, e, n - 1, 0),
                              vc_bvExtract(vc, e, bw - 1, n));
      }
    }
    else if (kind == Op::BV_REPEAT)
    {
      assert(n_args == 1);
      assert(indices.size() == 1);
      MURXLA_TEST(indices[0] >= 1);
      res = stp_args[0];
      for (uint32_t i = 1; i < indices[0]; ++i)
      {
        res = vc_bvConcatExpr(vc, res, stp_args[0]);
      }
    }
    /* Solver-specific operators */
    else if (kind == OP_UADDO)
    {
      assert(n_args == 2);
      res = vc_bvUnsignedAddOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == OP_SADDO)
    {
      assert(n_args == 2);
      res = vc_bvSignedAddOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == OP_USUBO)
    {
      assert(n_args == 2);
      res = vc_bvUnsignedSubOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == OP_SSUBO)
    {
      assert(n_args == 2);
      res = vc_bvSignedSubOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == OP_UMULO)
    {
      assert(n_args == 2);
      res = vc_bvUnsignedMulOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else if (kind == OP_SMULO)
    {
      assert(n_args == 2);
      res = vc_bvSignedMulOverflowExpr(vc, stp_args[0], stp_args[1]);
    }
    else
    {
      MURXLA_CHECK_CONFIG(false)
          << "StpSolver: unsupported operator kind '" << kind << "'";
    }
  }
  MURXLA_TEST(res != nullptr);
  auto res_term = std::shared_ptr<StpTerm>(new StpTerm(res));
  /* Array-valued results report ARRAY_TYPE with no element/index sort detail on
   * the STP node (get_sort could only recover widths, not FP/RM element/index
   * kinds), so attach the full Murxla array sort here from the operands. */
  if (kind == Op::ARRAY_STORE)
  {
    res_term->set_sort(args[0]->get_sort());
  }
  else if (kind == Op::ITE && args[1]->get_sort()->is_array())
  {
    res_term->set_sort(args[1]->get_sort());
  }
  return res_term;
}

bool
StpSolver::can_apply(const Op::Kind& kind,
                     const std::vector<Term>& args,
                     const std::vector<uint32_t>& indices) const
{
  (void) indices;
#ifdef MURXLA_STP_HAVE_FP
  if (kind == Op::FP_REM)
  {
    /* STP blasts fp.rem by unrolling one divide step per representable
     * exponent difference: 2^eb + sb - 4 steps, capped at REM_UNROLL_LIMIT
     * (2304); see STP's FloatBlaster::remSupported. vc_fpRemExpr raises a
     * FatalError above that (i.e. for formats larger than binary64), which
     * would abort the whole fuzzer, so decline it here and let the generator
     * pick something else. */
    assert(args.size() == 2);
    Sort s = args[0]->get_sort();
    assert(s->is_fp());
    uint64_t steps = (uint64_t{1} << s->get_fp_exp_size())
                     + s->get_fp_sig_size() - 4;
    if (steps > 2304) return false;
  }
#else
  (void) kind;
  (void) args;
#endif
  return true;
}

bool
StpSolver::can_get_value(const Term& term) const
{
#ifdef MURXLA_STP_HAVE_UF
  /* Only a *bare* uninterpreted-function application can lack a value: one
   * the most recent certified solve never reached has none of its own, and
   * that is not predictable from the assertions, because STP's simplifier
   * drops applications under, e.g., a dead ite branch or a trivially true
   * disjunction. A term built *over* an application is always evaluable --
   * the enclosing operator needs a constant operand, so STP completes an
   * unreached application through its certified function model.
   *
   * Ask STP rather than guess. The probe reports a nonfatal diagnostic when
   * it declines, which is expected here and not worth printing, so silence
   * the handler across the call only -- genuine diagnostics elsewhere still
   * reach stderr. */
  StpTerm* t = checked_cast<StpTerm*>(term.get());
  assert(t);
  if (!t->is_uf_decl() && getExprKind(StpTerm::get_stp_term(term)) == UF_APPLY)
  {
    vc_registerErrorHandler(ignore_diagnostic);
    Expr value =
        vc_getUninterpretedFunctionValue(d_solver, StpTerm::get_stp_term(term));
    vc_registerErrorHandler(nullptr);
    if (value == nullptr) return false;
    vc_DeleteExpr(value);
  }
#else
  (void) term;
#endif
  return true;
}

Sort
StpSolver::get_sort(Term term, SortKind sort_kind)
{
  Expr e = StpTerm::get_stp_term(term);
#ifdef MURXLA_STP_HAVE_UF
  /* A declaration handle is an ordinary STP symbol reserved as the function's
   * identity and carries no function type, so the node cannot describe the
   * signature. mk_const attaches the full Murxla sort at creation; hand that
   * back rather than inspecting the node. */
  if (sort_kind == SORT_FUN)
  {
    Sort s = term->get_sort();
    assert(s != nullptr && s->is_fun());
    return s;
  }
#endif
#ifdef MURXLA_STP_HAVE_FP
  /* A RoundingMode term is represented as a 5-bit bit-vector in STP; the
   * requested sort kind is what disambiguates it from a genuine bit-vector. */
  if (sort_kind == SORT_RM)
  {
    return std::shared_ptr<StpSort>(new StpSort(SORT_RM));
  }
  if (getType(e) == FLOATINGPOINT_TYPE)
  {
    return std::shared_ptr<StpSort>(
        new StpSort(SORT_FP,
                    static_cast<uint32_t>(vc_getExpWidth(e)),
                    static_cast<uint32_t>(vc_getSigWidth(e))));
  }
#endif
  switch (getType(e))
  {
    case BOOLEAN_TYPE: return std::shared_ptr<StpSort>(new StpSort());
    case BITVECTOR_TYPE:
      return std::shared_ptr<StpSort>(
          new StpSort(static_cast<uint32_t>(getVWidth(e))));
    case ARRAY_TYPE:
    {
      /* Fallback for bit-vector arrays. FP/RM-element/index arrays get their
       * full sort attached at creation time (see mk_term), so they do not
       * reach here -- the STP node only exposes widths, not element/index
       * sort kinds. */
      Sort index = std::shared_ptr<StpSort>(
          new StpSort(static_cast<uint32_t>(getIWidth(e))));
      Sort element = std::shared_ptr<StpSort>(
          new StpSort(static_cast<uint32_t>(getVWidth(e))));
      return std::shared_ptr<StpSort>(new StpSort(index, element));
    }
    default:
      MURXLA_CHECK_CONFIG(false)
          << "StpSolver: term of unknown type in get_sort";
  }
  return nullptr;
}

void
StpSolver::assert_formula(const Term& t)
{
  pop_pending_assumption_scope();
  vc_assertFormula(d_solver, StpTerm::get_stp_term(t));
}

Solver::Result
StpSolver::check_sat()
{
  pop_pending_assumption_scope();
  int32_t res;
  Expr ff = vc_falseExpr(d_solver);
  if (d_rng.pick_with_prob(100))
  {
    res = vc_query_with_timeout(
        d_solver, ff, static_cast<int32_t>(d_rng.pick<uint32_t>(0, 10000)), -1);
  }
  else
  {
    res = vc_query(d_solver, ff);
  }
  if (res == 0) return Result::SAT;
  if (res == 1) return Result::UNSAT;
  MURXLA_TEST(res == 3);
  return Result::UNKNOWN;
}

Solver::Result
StpSolver::check_sat_assuming(const std::vector<Term>& assumptions)
{
  /* STP has no native assumption interface. Emulate check-sat-assuming with
   * a scope that is popped (lazily, see pop_pending_assumption_scope()) as
   * soon as the next context-modifying operation happens. The lazy pop keeps
   * the counterexample valid for model queries after a 'sat' result. */
  pop_pending_assumption_scope();
  vc_push(d_solver);
  d_pending_assumption_pop = true;
  for (const Term& t : assumptions)
  {
    vc_assertFormula(d_solver, StpTerm::get_stp_term(t));
  }
  int32_t res = vc_query(d_solver, vc_falseExpr(d_solver));
  if (res == 0) return Result::SAT;
  if (res == 1) return Result::UNSAT;
  MURXLA_TEST(res == 3);
  return Result::UNKNOWN;
}

std::vector<Term>
StpSolver::get_unsat_assumptions()
{
  /* Unsat assumptions are never enabled for STP. */
  return std::vector<Term>();
}

std::vector<Term>
StpSolver::get_value(const std::vector<Term>& terms)
{
  std::vector<Term> res;
  for (const Term& t : terms)
  {
    Expr value = vc_getCounterExample(d_solver, StpTerm::get_stp_term(t));
    /* Since the UFSTP v2 API, an unanswerable model query is nonfatal and
     * yields NULL rather than aborting. can_get_value keeps UF-bearing terms
     * away from here, so a NULL is a genuine failure to report. */
    MURXLA_TEST(value != nullptr);
    res.push_back(std::shared_ptr<StpTerm>(new StpTerm(value)));
  }
  return res;
}

void
StpSolver::push(uint32_t n_levels)
{
  pop_pending_assumption_scope();
  for (uint32_t i = 0; i < n_levels; ++i)
  {
    vc_push(d_solver);
  }
}

void
StpSolver::pop(uint32_t n_levels)
{
  pop_pending_assumption_scope();
  for (uint32_t i = 0; i < n_levels; ++i)
  {
    vc_pop(d_solver);
  }
}

void
StpSolver::print_model()
{
  vc_printCounterExample(d_solver);
}

void
StpSolver::reset()
{
  d_pending_assumption_pop = false;
  vc_Destroy(d_solver);
  d_solver = nullptr;
  new_solver();
}

void
StpSolver::reset_assertions()
{
  /* Not supported, action is disabled. */
  assert(false);
}

}  // namespace stp
}  // namespace murxla

#endif
