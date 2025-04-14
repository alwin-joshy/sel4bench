#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(scratch C)

set(configure_string "")
config_option(
    AppScratchBench
    APP_SCRATCHBENCH
    "Scratchpad for experimental benchmarks"
    DEFAULT
    OFF
    DEPENDS
    "DefaultBenchDeps"
)
add_config_library(sel4benchscratch "${configure_string}")

file(GLOB deps src/*.c)
list(SORT deps)
add_executable(scratch EXCLUDE_FROM_ALL ${deps})
target_link_libraries(
    scratch
    sel4_autoconf
    sel4benchscratch_Config
    sel4
    sel4bench
    muslc
    sel4vka
    utils
    elf
    sel4allocman
    sel4utils
    sel4simple
    sel4muslcsys
    sel4platsupport
    platsupport
    sel4vspace
    sel4benchsupport
    sel4debug
)

if(AppScratchBench)
    set_property(GLOBAL APPEND PROPERTY sel4benchapps_property "$<TARGET_FILE:scratch>")
endif()
