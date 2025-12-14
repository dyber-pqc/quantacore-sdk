#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "quac100pp::quac100pp_static" for configuration "Release"
set_property(TARGET quac100pp::quac100pp_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(quac100pp::quac100pp_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/quac100pp.lib"
  )

list(APPEND _cmake_import_check_targets quac100pp::quac100pp_static )
list(APPEND _cmake_import_check_files_for_quac100pp::quac100pp_static "${_IMPORT_PREFIX}/lib/quac100pp.lib" )

# Import target "quac100pp::quac100pp_shared" for configuration "Release"
set_property(TARGET quac100pp::quac100pp_shared APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(quac100pp::quac100pp_shared PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/quac100pp.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/quac100pp.dll"
  )

list(APPEND _cmake_import_check_targets quac100pp::quac100pp_shared )
list(APPEND _cmake_import_check_files_for_quac100pp::quac100pp_shared "${_IMPORT_PREFIX}/lib/quac100pp.lib" "${_IMPORT_PREFIX}/bin/quac100pp.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
