# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/admin-lcyl/Bureau/BDT/BDTResult

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/admin-lcyl/Bureau/BDT/BDTResult/build

# Include any dependencies generated for this target.
include CMakeFiles/bdt_result_prefinal.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bdt_result_prefinal.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bdt_result_prefinal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bdt_result_prefinal.dir/flags.make

CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o: CMakeFiles/bdt_result_prefinal.dir/flags.make
CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o: ../bdt_result_prefinal.cpp
CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o: CMakeFiles/bdt_result_prefinal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/admin-lcyl/Bureau/BDT/BDTResult/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o -MF CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o.d -o CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o -c /home/admin-lcyl/Bureau/BDT/BDTResult/bdt_result_prefinal.cpp

CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/admin-lcyl/Bureau/BDT/BDTResult/bdt_result_prefinal.cpp > CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.i

CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/admin-lcyl/Bureau/BDT/BDTResult/bdt_result_prefinal.cpp -o CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.s

# Object files for target bdt_result_prefinal
bdt_result_prefinal_OBJECTS = \
"CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o"

# External object files for target bdt_result_prefinal
bdt_result_prefinal_EXTERNAL_OBJECTS =

bdt_result_prefinal: CMakeFiles/bdt_result_prefinal.dir/bdt_result_prefinal.cpp.o
bdt_result_prefinal: CMakeFiles/bdt_result_prefinal.dir/build.make
bdt_result_prefinal: /usr/local/lib/libOPENFHEpke.so.1.1.2
bdt_result_prefinal: /usr/local/lib/libOPENFHEbinfhe.so.1.1.2
bdt_result_prefinal: /usr/local/lib/libOPENFHEcore.so.1.1.2
bdt_result_prefinal: CMakeFiles/bdt_result_prefinal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/admin-lcyl/Bureau/BDT/BDTResult/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bdt_result_prefinal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bdt_result_prefinal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bdt_result_prefinal.dir/build: bdt_result_prefinal
.PHONY : CMakeFiles/bdt_result_prefinal.dir/build

CMakeFiles/bdt_result_prefinal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bdt_result_prefinal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bdt_result_prefinal.dir/clean

CMakeFiles/bdt_result_prefinal.dir/depend:
	cd /home/admin-lcyl/Bureau/BDT/BDTResult/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/admin-lcyl/Bureau/BDT/BDTResult /home/admin-lcyl/Bureau/BDT/BDTResult /home/admin-lcyl/Bureau/BDT/BDTResult/build /home/admin-lcyl/Bureau/BDT/BDTResult/build /home/admin-lcyl/Bureau/BDT/BDTResult/build/CMakeFiles/bdt_result_prefinal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bdt_result_prefinal.dir/depend
