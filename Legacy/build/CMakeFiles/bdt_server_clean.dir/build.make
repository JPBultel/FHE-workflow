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
CMAKE_SOURCE_DIR = /home/admin-lcyl/Bureau/OpenFHEUser

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/admin-lcyl/Bureau/OpenFHEUser/build

# Include any dependencies generated for this target.
include CMakeFiles/bdt_server_clean.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bdt_server_clean.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bdt_server_clean.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bdt_server_clean.dir/flags.make

CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o: CMakeFiles/bdt_server_clean.dir/flags.make
CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o: ../bdt_server_clean.cpp
CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o: CMakeFiles/bdt_server_clean.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/admin-lcyl/Bureau/OpenFHEUser/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o -MF CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o.d -o CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o -c /home/admin-lcyl/Bureau/OpenFHEUser/bdt_server_clean.cpp

CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/admin-lcyl/Bureau/OpenFHEUser/bdt_server_clean.cpp > CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.i

CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/admin-lcyl/Bureau/OpenFHEUser/bdt_server_clean.cpp -o CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.s

# Object files for target bdt_server_clean
bdt_server_clean_OBJECTS = \
"CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o"

# External object files for target bdt_server_clean
bdt_server_clean_EXTERNAL_OBJECTS =

bdt_server_clean: CMakeFiles/bdt_server_clean.dir/bdt_server_clean.cpp.o
bdt_server_clean: CMakeFiles/bdt_server_clean.dir/build.make
bdt_server_clean: /usr/local/lib/libOPENFHEpke.so.1.1.2
bdt_server_clean: /usr/local/lib/libOPENFHEbinfhe.so.1.1.2
bdt_server_clean: /usr/local/lib/libOPENFHEcore.so.1.1.2
bdt_server_clean: CMakeFiles/bdt_server_clean.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/admin-lcyl/Bureau/OpenFHEUser/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bdt_server_clean"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bdt_server_clean.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bdt_server_clean.dir/build: bdt_server_clean
.PHONY : CMakeFiles/bdt_server_clean.dir/build

CMakeFiles/bdt_server_clean.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bdt_server_clean.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bdt_server_clean.dir/clean

CMakeFiles/bdt_server_clean.dir/depend:
	cd /home/admin-lcyl/Bureau/OpenFHEUser/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/admin-lcyl/Bureau/OpenFHEUser /home/admin-lcyl/Bureau/OpenFHEUser /home/admin-lcyl/Bureau/OpenFHEUser/build /home/admin-lcyl/Bureau/OpenFHEUser/build /home/admin-lcyl/Bureau/OpenFHEUser/build/CMakeFiles/bdt_server_clean.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bdt_server_clean.dir/depend

