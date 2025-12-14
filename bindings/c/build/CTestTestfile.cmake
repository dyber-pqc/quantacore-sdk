# CMake generated Testfile for 
# Source directory: D:/quantacore-sdk/bindings/c
# Build directory: D:/quantacore-sdk/bindings/c/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(quac100_tests "D:/quantacore-sdk/bindings/c/build/Debug/test_quac100.exe")
  set_tests_properties(quac100_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/quantacore-sdk/bindings/c/CMakeLists.txt;133;add_test;D:/quantacore-sdk/bindings/c/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(quac100_tests "D:/quantacore-sdk/bindings/c/build/Release/test_quac100.exe")
  set_tests_properties(quac100_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/quantacore-sdk/bindings/c/CMakeLists.txt;133;add_test;D:/quantacore-sdk/bindings/c/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(quac100_tests "D:/quantacore-sdk/bindings/c/build/MinSizeRel/test_quac100.exe")
  set_tests_properties(quac100_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/quantacore-sdk/bindings/c/CMakeLists.txt;133;add_test;D:/quantacore-sdk/bindings/c/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(quac100_tests "D:/quantacore-sdk/bindings/c/build/RelWithDebInfo/test_quac100.exe")
  set_tests_properties(quac100_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/quantacore-sdk/bindings/c/CMakeLists.txt;133;add_test;D:/quantacore-sdk/bindings/c/CMakeLists.txt;0;")
else()
  add_test(quac100_tests NOT_AVAILABLE)
endif()
