###
# Murxla: A Model-Based API Fuzzer for SMT solvers.
#
# This file is part of Murxla.
#
# Copyright (C) 2019-2022 by the authors listed in the AUTHORS file.
#
# See LICENSE for more information on using this software.
##

set(murxla_src_files
  action.cpp
  dd.cpp
  except.cpp
  fsm.cpp
  main.cpp
  murxla.cpp
  op.cpp
  result.cpp
  rng.cpp
  solver_manager.cpp
  solver_option.cpp
  sort.cpp
  statistics.cpp
  term_db.cpp
  theory.cpp
  util.cpp
  solver/solver.cpp
  solver/btor/btor_solver.cpp
  solver/bitwuzla/bitwuzla_solver.cpp
  solver/cvc5/cvc5_solver.cpp
  solver/cvc5/cvc5_tracer.cpp
  solver/yices/yices_solver.cpp
  solver/smt2/smt2_solver.cpp
  solver/stp/stp_solver.cpp
  solver/meta/check_solver.cpp
  solver/meta/shadow_solver.cpp
  solver/solver_profile.cpp
)

# Setup JSON library
include(${PROJECT_SOURCE_DIR}/cmake/json.cmake)

add_executable(murxla ${murxla_src_files})
target_include_directories(murxla PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(murxla PRIVATE nlohmann_json::nlohmann_json)

if(GCOV)
  target_compile_definitions(murxla PUBLIC MURXLA_COVERAGE)
endif()

if (NOT APPLE)
  include(CheckIncludeFileCXX)
  # Workaround to support compilation with gcc7.
  check_include_file_cxx(<filesystem> HAVE_FILESYSTEM_INCLUDE)
  if(NOT HAVE_FILESYSTEM_INCLUDE)
    target_link_libraries(murxla PRIVATE stdc++fs)
  endif()
endif()

if(Boolector_FOUND)
  target_link_libraries(murxla PRIVATE Boolector::boolector)
  target_compile_definitions(murxla PUBLIC MURXLA_USE_BOOLECTOR)
endif()

if(Bitwuzla_FOUND)
  target_link_libraries(murxla PRIVATE PkgConfig::Bitwuzla)
  target_compile_definitions(murxla PUBLIC MURXLA_USE_BITWUZLA)
endif()

if(cvc5_FOUND)
  target_link_libraries(murxla PRIVATE cvc5::cvc5)
  target_compile_definitions(murxla PUBLIC MURXLA_USE_CVC5)
endif()

if (Yices_FOUND)
  target_include_directories(murxla PRIVATE ${Yices_INCLUDE_DIR})
  target_link_libraries(murxla PRIVATE ${Yices_LIBRARIES})
  target_compile_definitions(murxla PUBLIC MURXLA_USE_YICES)
endif()

if (STP_FOUND)
  target_include_directories(murxla PRIVATE ${STP_INCLUDE_DIR})
  target_link_libraries(murxla PRIVATE ${STP_LIBRARIES})
  target_compile_definitions(murxla PUBLIC MURXLA_USE_STP)

  # Detect optional STP capabilities from the linked library so a single
  # wrapper adapts to master / symfpu / array-extensionality builds.
  include(CheckCXXSymbolExists)
  include(CMakePushCheckState)
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES ${STP_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${STP_LIBRARIES})
  check_cxx_symbol_exists(vc_fpType
    "stp/c_interface.h" STP_HAVE_FPTYPE)
  check_cxx_symbol_exists(vc_fpRoundingModeVar
    "stp/c_interface.h" STP_HAVE_FP_RMVAR)
  check_cxx_symbol_exists(vc_deleteCounterExampleArray
    "stp/c_interface.h" STP_HAVE_ARRAY_EX)
  cmake_pop_check_state()

  # Incremental solving added no new C-API symbol, so detect it by the presence
  # of its public header (the same branch adds the 'i' flag that process_argument
  # otherwise rejects with exit(-1)). A plain existence check, not a compile
  # test: the header pulls in the generated ASTKind.h, which lives in STP's
  # build tree rather than its include dir.
  if (EXISTS "${STP_INCLUDE_DIR}/stp/Incremental/IncrementalSolver.h")
    set(STP_HAVE_INCREMENTAL TRUE)
  endif()

  if (STP_HAVE_FPTYPE AND STP_HAVE_FP_RMVAR)
    target_compile_definitions(murxla PUBLIC MURXLA_STP_HAVE_FP)
    message(STATUS "STP: floating-point support detected")
  endif()
  if (STP_HAVE_ARRAY_EX)
    target_compile_definitions(murxla PUBLIC MURXLA_STP_HAVE_ARRAY_EX)
    message(STATUS "STP: array-extensionality support detected")
  endif()
  if (STP_HAVE_INCREMENTAL)
    target_compile_definitions(murxla PUBLIC MURXLA_STP_HAVE_INCREMENTAL)
    message(STATUS "STP: incremental-solving support detected")
  endif()
endif()

# Generate solver profile headers
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/gen_profile.cmake"
  CONTENT [[
file(READ ${PROFILE_INPUT_FILE} JSON)
set(PROFILE "\
#include <string>\n\
namespace murxla {\n\
namespace ${SOLVER} {\n\
  static const std::string s_profile=R\"PROFILE(${JSON})PROFILE\";\n\
}\n}\n")
file(WRITE "${PROFILE_OUTPUT_FILE}" "${PROFILE}")]]
)

foreach(solver btor bitwuzla cvc5 yices smt2 stp)
  set(JSON_FILE
      "${CMAKE_CURRENT_SOURCE_DIR}/solver/${solver}/profile.json")
  set(PROFILE_HEADER_FILE
      "${CMAKE_CURRENT_BINARY_DIR}/solver/${solver}/profile.hpp")

  add_custom_command(
    OUTPUT ${PROFILE_HEADER_FILE}
    COMMAND
      ${CMAKE_COMMAND}
        -DSOLVER="${solver}"
        -DPROFILE_INPUT_FILE="${JSON_FILE}"
        -DPROFILE_OUTPUT_FILE="${PROFILE_HEADER_FILE}"
        -P gen_profile.cmake
    DEPENDS ${JSON_FILE} gen_profile.cmake
  )
  add_custom_target(gen-profile-${solver} DEPENDS ${PROFILE_HEADER_FILE})
  add_dependencies(murxla gen-profile-${solver})
endforeach()
target_include_directories(murxla PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
