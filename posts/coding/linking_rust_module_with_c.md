+++
title = "Linking Rust Module With C"
summary = "Building and Linking Rust Module with a C binary using CMake Presets"
cover_image_url = "/post_assets/Linking_Rust_Module_With_C/rustacean-flat-happy.png"
creation_date = 2023-07-17T18:00:30Z
modified_date = 2023-07-17T18:05:16Z
+++
## Linking Rust Module With CMake Built C Project

One of the benefits with Rust is the ability to compile to a C ABI compatible Libray and call Rust code from a C
program or Libray. In this post we will build a C program with CMake and a Rust module that compiles to a C
compatible Static library, which is built and linked with CMake.

### The CMake Part

***

First we need to create a CMakeLists.txt setup to build a set of source files and then link and include a subdirectory containing the Rust module.

```cmake
cmake_minimum_required(VERSION 3.22)
project(rusty_c C CXX ASM)
include(ExternalProject)

set(CMAKE_COLOR_DIAGNOSTICS ON)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(rusty_c)
target_sources(rusty_c 
	PUBLIC src/main.c
)
target_link_libraries(rusty_c
	rust_hello_world
)

add_subdirectory(lib/rust_hello_world)
```

*CMakeLists.txt*

In this Case rusty_c is the main executable, and rust_hello_world is our Rust static library.

Next we will create a CMakePresets.json file for convience and easier configuration and building, this also makes having different configurations for debug and production code easier

```json
{
	"version": 5,
	"cmakeMinimumRequired": {
		"major": 3,
		"minor": 24,
		"patch": 0
	},
	"configurePresets": [
		{
			"name": "default",
			"displayName": "Default Config",
			"description": "Configure preset using Ninja generator",
			"generator": "Ninja",
			"binaryDir": "${sourceDir}/build/default/release",
			"cacheVariables": {
				"CMAKE_BUILD_TYPE": "Release",
				"CMAKE_EXPORT_COMPILE_COMMANDS": {
					"type": "BOOL",
					"value": "ON"
				}
			}
		},
		{
			"name": "debug",
			"displayName": "Debug Config",
			"description": "Configure preset using Ninja generator",
			"generator": "Ninja",
			"binaryDir": "${sourceDir}/build/default/debug",
			"cacheVariables": {
				"CMAKE_BUILD_TYPE": "Debug",
				"CMAKE_EXPORT_COMPILE_COMMANDS": {
					"type": "BOOL",
					"value": "ON"
				}
			}
		}
	],
	"buildPresets": [
		{
			"name": "default",
			"configurePreset": "default"
		},
		{
			"name": "debug",
			"configurePreset": "debug"
		}
	]
}
```

*CMakePresets.json*

For this example we will use the Ninja generator, this can be changed to Unix Makefile if you prefer.
We also set the default preset to be a release build as well as the location where the binary should be build

### The Rust Part

***

Next lets create the rust project that will be linked.
Create and cd into a lib folder then run

```bash
cargo new --lib rust_hello_world
```

Next we need to add "crate-type = ["staticlib"]" to our Cargo.toml, it should now look like this.

```toml
[package]
name = "rust_hello_world"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
```

*Cargo.toml*

Next create a CMakeLists.txt file in lib/rust_hello_world. In here we will create an external project and tell CMake how to build it.
Then create a CMake interface library that will be linked by the C program.
We add src as an include dir in rust_hello_world so that we include API definition header files for C

```cmake
#Define Rust as external project 
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)
ExternalProject_Add(
    rust_hello_world_ep
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build COMMAND cargo build --release
    BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}
	BUILD_ALWAYS ON
	BUILD_BYPRODUCTS   ${CMAKE_CURRENT_LIST_DIR}/target/release/librust_hello_world.a ${CMAKE_CURRENT_LIST_DIR}/target/debug/librust_hello_world.a
    INSTALL_COMMAND ""
)
#create interface Lib linking External lib, so that main Cmakelist can just link library as usual
add_library(rust_hello_world INTERFACE)
add_dependencies(rust_hello_world INTERFACE rust_hello_world_ep)
target_include_directories(rust_hello_world INTERFACE 
    src
)
target_link_libraries(rust_hello_world INTERFACE
    debug "${CMAKE_CURRENT_LIST_DIR}/target/debug/librust_hello_world.a"
    optimized "${CMAKE_CURRENT_LIST_DIR}/target/release/librust_hello_world.a"
)
```

*lib/rust_hello_world/CMakeLists.txt*

Now lets create our function we want to export in lib.rs, adding "#[no_mangle]" and "extern "C"" to make sure it is compiled in the correct format for C.

```rust
#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello From Rust!");
}
```

*lib/rust_hello_world/src/lib.rs*

Now create a rust_hello_world_api.h in our src directory.
This is a C header file and in here we will defined the interface for the program we created.

```c
#pragma once
extern void hello_from_rust(void);
```

*lib/rust_hello_world/src/rust_hello_world_api.h*

### The C Part

***

Finally we can create our main.c file and write the program that will actually use the Rust Library

```c
#include <stdio.h>
#include "rust_hello_world_api.h"


int main(int argc, char *argv[])
{
  printf("Hello From C!\n");
  hello_from_rust();
  return 0;
}
```

*src/main.c*

This particular program is pretty simple.
All we do is include out api header file and then call the function declared in it.

now to configure and run this program we just need to run

```bash
cmake --preset default
cmake --build --preset default
```

You should now have a built binary in build/default/release

Full code can be found [Here](https://github.com/PGIII/c_rust_template)
