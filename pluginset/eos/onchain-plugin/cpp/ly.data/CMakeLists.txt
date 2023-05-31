# set(EOSIO_WASM_OLD_BEHAVIOR "Off")
# find_package( eosio.cdt REQUIRED )
if (EOSIO_COMPILE_TEST_CONTRACTS)

   add_contract(ly.data ly.data ${CMAKE_CURRENT_SOURCE_DIR}/src/ly.data.cpp)

   target_include_directories(ly.data
      PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include)

   set_target_properties(ly.data
      PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

   # configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/ricardian/ly.data.contracts.md.in ${CMAKE_CURRENT_BINARY_DIR}/ricardian/ly.data.contracts.md @ONLY )

   target_compile_options( ly.data PUBLIC )
   # target_compile_options( ly.data PUBLIC -R${CMAKE_CURRENT_SOURCE_DIR}/ricardian -R${CMAKE_CURRENT_BINARY_DIR}/ricardian )

else()
   configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/bin/ly.data.abi ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY )
   configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/bin/ly.data.wasm ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY )
endif()  