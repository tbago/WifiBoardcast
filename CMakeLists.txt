cmake_minimum_required(VERSION 3.16)

project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 17)

include(WBLib.cmake)

add_executable(wfb_tx executables/wfb_tx.cpp)
target_link_libraries(wfb_tx ${WB_TARGET_LINK_LIBRARIES})

add_executable(wfb_rx executables/wfb_rx.cpp)
target_link_libraries(wfb_rx ${WB_TARGET_LINK_LIBRARIES})

add_executable(wfb_keygen executables/wfb_keygen.c)
target_link_libraries(wfb_keygen ${WB_TARGET_LINK_LIBRARIES})

#add_executable(benchmark_fec executables/benchmark_fec.cpp)
#target_link_libraries(benchmark_fec  ${WB_TARGET_LINK_LIBRARIES})

#add_executable(udp_generator_validator executables/udp_generator_validator.cpp)
#target_link_libraries(udp_generator_validator  ${WB_TARGET_LINK_LIBRARIES})

#add_executable(unit_test executables/unit_test.cpp)
#target_link_libraries(unit_test  ${WB_TARGET_LINK_LIBRARIES})

#add_executable(socket_helper_test executables/socket_helper_test.cpp)
#target_link_libraries(socket_helper_test ${WB_TARGET_LINK_LIBRARIES})

#add_executable(udp_packet_drop_util executables/udp_packet_drop_util.cpp)
#target_link_libraries(udp_packet_drop_util ${WB_TARGET_LINK_LIBRARIES})

message(STATUS "${CMAKE_BINARY_DIR}")


file(COPY ${CMAKE_SOURCE_DIR}/scripts/enable_monitor_mode.sh DESTINATION ${CMAKE_BINARY_DIR}/)
file(COPY ${CMAKE_SOURCE_DIR}/scripts/start_rx.sh DESTINATION ${CMAKE_BINARY_DIR}/)
file(COPY ${CMAKE_SOURCE_DIR}/scripts/start_tx.sh DESTINATION ${CMAKE_BINARY_DIR}/)
