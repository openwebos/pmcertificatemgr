# @@@LICENSE
#
#      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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

# PmCertificateMgrTest is an executable for stand-alone testing and
# debugging.  This program is unsupported.  It is provided here to
# assist in debugging the library.
#
# To build, in top-level CMakeLists.txt,
#   * add src/cert_debug.c to the library.
#   * uncomment add_subdirectory(src/test ...)
#   * ensure that D_DEBUG_ENABLED is defined, for example, run cmake as:
#	cmake D_DEBUG_ENABLED ..
#   * Re-build the library and install, then make PmCertificateMgrTest.
#
add_executable(PmCertificateMgrTest PmCertificateMgr.c)
target_link_libraries(PmCertificateMgrTest ${OPENSSL_LDFLAGS})
target_link_libraries(PmCertificateMgrTest -L@WEBOS_INSTALL_ROOT@/usr/lib PmCertificateMgr)

