# @@@LICENSE
#
#      Copyright (c) 2008-2013 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

cmake_minimum_required(VERSION 2.8.7)

project(PmCertificateMgr C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC2)
webos_component(2 0 0)
webos_machine_impl_dep()

webos_build_pkgconfig()

include(FindPkgConfig)
pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

include_directories(include/public)
webos_add_compiler_flags(ALL -Wall -O0 -g)
webos_add_linker_options(ALL --version-script=${CMAKE_SOURCE_DIR}/src/PmCertificateMgrExports.map)
webos_add_linker_options(ALL --no-undefined -O0 -g)

if(${WEBOS_TARGET_MACHINE_IMPL} STREQUAL simulator)
	webos_add_compiler_flags(ALL  -fno-exceptions)
	webos_add_linker_options(ALL  -fno-exceptions)
endif()

add_definitions(-DCERT_DEF_CONF_FILE="${WEBOS_INSTALL_SYSCONFDIR}/ssl/openssl.cnf")

add_library(PmCertificateMgr SHARED src/cert_cfg.c src/cert_db.c src/cert_mgr.c src/cert_pkcs.c src/cert_utils.c src/cert_x509.c )
target_link_libraries(PmCertificateMgr ${OPENSSL_LDFLAGS})

webos_build_library()
webos_config_build_doxygen(doc Doxyfile)

