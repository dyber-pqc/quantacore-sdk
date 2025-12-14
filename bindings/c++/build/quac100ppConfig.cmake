
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was quac100ppConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

include(CMakeFindDependencyMacro)

# Find the C library dependency
find_dependency(quac100 QUIET)

include("${CMAKE_CURRENT_LIST_DIR}/quac100ppTargets.cmake")

check_required_components(quac100pp)

# Provide version info
set(QUAC100PP_VERSION 1.0.0)
set(QUAC100PP_VERSION_MAJOR 1)
set(QUAC100PP_VERSION_MINOR 0)
set(QUAC100PP_VERSION_PATCH 0)
