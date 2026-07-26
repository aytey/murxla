###
# Murxla: A Model-Based API Fuzzer for SMT solvers.
#
# This file is part of Murxla.
#
# Copyright (C) 2019-2022 by the authors listed in the AUTHORS file.
#
# See LICENSE for more information on using this software.
##
# Find STP
# STP_FOUND - found STP lib
# STP_INCLUDE_DIR - the STP include directory
# STP_LIBRARIES - Libraries needed to use STP

find_path(STP_INCLUDE_DIR NAMES stp/c_interface.h)
find_library(STP_LIBRARIES NAMES stp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(STP
  DEFAULT_MSG STP_INCLUDE_DIR STP_LIBRARIES)

mark_as_advanced(STP_INCLUDE_DIR STP_LIBRARIES)
