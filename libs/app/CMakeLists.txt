# Application protocol - layer 2 over user messages (see docs/app-protocol.md).
# Frame codec, type registry, dispatcher, and the built-in message handlers.
# Depends only on core (PeerId) and msg (Suite); it never reaches into libs/net,
# so message types stay independent of the transport.
add_library(tier_app STATIC
  src/frame.cpp
  src/dispatcher.cpp
  src/handlers/text.cpp
  src/handlers/receipt.cpp)
add_library(tier::app ALIAS tier_app)

target_include_directories(tier_app PUBLIC include)
target_link_libraries(tier_app PUBLIC tier::core tier::msg tier::options)
