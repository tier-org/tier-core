# SQLite built from the vendored public-domain amalgamation (sqlite3.c/.h). Used
# only by tier-messenger for its local store; nothing on the node depends on it.
# Warnings in the amalgamation are not ours to fix, so the C file is compiled
# quietly; a small set of compile-time options trims the build and tightens
# defaults.
add_library(tier_sqlite STATIC sqlite3.c)
add_library(tier::sqlite ALIAS tier_sqlite)

target_include_directories(tier_sqlite PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(tier_sqlite PRIVATE
  SQLITE_THREADSAFE=1              # the stream reader and UI touch it from two threads
  SQLITE_DQS=0                     # no double-quoted string literals (catch typos)
  SQLITE_DEFAULT_FOREIGN_KEYS=1
  SQLITE_OMIT_LOAD_EXTENSION=1
  SQLITE_OMIT_DEPRECATED=1
  SQLITE_USE_URI=1)
# Vendored C: silence its warnings, keep it position-independent for linking into
# the client. Threads for SQLITE_THREADSAFE.
target_compile_options(tier_sqlite PRIVATE -w)
set_target_properties(tier_sqlite PROPERTIES POSITION_INDEPENDENT_CODE ON)
find_package(Threads REQUIRED)
target_link_libraries(tier_sqlite PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
