# TrailDrop firmware CMakeLists.txt
# Exclude main_full.cpp from build (use main_test.cpp as entry point)

FILE(GLOB_RECURSE app_sources_all ${CMAKE_SOURCE_DIR}/src/*.*)

# Filter out main_full.cpp
set(app_sources "")
foreach(source ${app_sources_all})
    get_filename_component(source_name ${source} NAME)
    if(NOT "${source_name}" STREQUAL "main_full.cpp")
        list(APPEND app_sources ${source})
    endif()
endforeach()

idf_component_register(SRCS ${app_sources})
