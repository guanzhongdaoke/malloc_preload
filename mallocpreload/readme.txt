1:.so
	gcc -fPIC -shared -o libmalloc_preload.so ./malloc_preload_localudp.c -ldl
2:exe CMakeLists.txt 
	-fno-omit-frame-pointer
	-g
	eg:
		cmake_minimum_required (VERSION 2.6)
		project (Hello)
		add_definitions("-Wall -W")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -Wextra -W -O0 -m64 -pthread -fno-omit-frame-pointer -rdynamic")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -W -O0 -m64 -pthread -fno-omit-frame-pointer -rdynamic")
		add_definitions("-Wall -std=c++11 -pthread") 
		add_executable(Hello Main.cpp)
